import json
import time
import logging
import splunklib.client as client

UNMASKED_SEARCH = "ITP - Unmasked Activity Report - Template"

SERVICE_REALM = "itp_secure_api"
SERVICE_USERNAME = "svc_itp_backend"

INDEX_PREFIX = "itp_pri_"
SOURCE_PREFIX = "Threat - "

JOB_TIMEOUT_SECONDS = 300

logger = logging.getLogger("splunk.itp")


class UnmaskedActivityReportHandler:

    def handle_POST(self, request, investigation_id):
        requester = request.get("user", "unknown")

        try:
            payload = json.loads(request.get("payload", "{}"))

            pri_raw = payload.get("pri_group_ids")
            member_firm = payload.get("member_firm")
            user = payload.get("user")
            maskmap = payload.get("maskmap")

            if not pri_raw or not member_firm or not user:
                raise Exception("Missing required parameters")

            pri_ids = [x.strip() for x in pri_raw.split(",") if x.strip()]

            service = self._connect_service_account(request)
            multisearch = self._build_multisearch(pri_ids, member_firm)

            job = service.saved_searches[UNMASKED_SEARCH].dispatch(
                **{
                    "args.multisearch": multisearch,
                    "args.maskmap": json.dumps(maskmap)
                }
            )

            self._wait(job)

            logger.info(json.dumps({
                "investigation_id": investigation_id,
                "event": "activity_report",
                "status": "success",
                "requester": requester,
                "user": user,
                "member_firm": member_firm,
                "pri_count": len(pri_ids),
                "sid": job.sid
            }))

            results = job.results(output_mode="csv", count=0)

            return {
                "status": 200,
                "headers": {
                    "Content-Type": "text/csv",
                    "Content-Disposition": f'attachment; filename="{user}.csv"'
                },
                "body": results.read()
            }

        except Exception as e:
            logger.warning(json.dumps({
                "investigation_id": investigation_id,
                "event": "activity_report",
                "status": "failed",
                "requester": requester,
                "error": str(e)
            }))
            return {
                "status": 400,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({
                    "error": str(e),
                    "investigation_id": investigation_id
                })
            }

    # --------------------------------------------------

    def _connect_service_account(self, request):
        service = client.connect(
            token=request["session"]["authtoken"],
            owner="nobody",
            app="itp"
        )

        for cred in service.storage_passwords:
            if cred.realm == SERVICE_REALM and cred.username == SERVICE_USERNAME:
                return client.connect(
                    username=SERVICE_USERNAME,
                    password=cred.clear_password,
                    host="localhost",
                    port=8089,
                    scheme="https",
                    app="itp"
                )

        raise Exception("Service credentials not found")

    # --------------------------------------------------

    def _build_multisearch(self, pri_ids, firm):
        searches = []

        for item in pri_ids:
            timestamp, pri_name, user_val = item.split("@@")
            earliest = int(timestamp)
            latest = earliest + 1

            search = (
                f'search index={INDEX_PREFIX}{firm} '
                f'earliest={earliest} latest={latest} '
                f'source="{SOURCE_PREFIX}{pri_name}*" '
                f'user={user_val}'
            )

            searches.append(f"[{search}]")

        if len(searches) == 1:
            return searches[0][1:-1]

        return "| multisearch " + " ".join(searches)

    # --------------------------------------------------

    def _wait(self, job):
        start = time.time()
        while not job.is_done():
            if time.time() - start > JOB_TIMEOUT_SECONDS:
                raise Exception("Search timeout")
            time.sleep(0.5)
            job.refresh()

        if job["dispatchState"] == "FAILED":
            raise Exception("Search job failed")
