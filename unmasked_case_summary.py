import json
import time
import logging
import splunklib.client as client

OPM_SEARCH = "ITP - OPM Private Lookup - Template"
MASKMAP_SEARCH = "ITP - Get Mask Map by ID - Template"

SERVICE_REALM = "itp_secure_api"
SERVICE_USERNAME = "svc_itp_backend"

TIME_OFFSET = 1
JOB_TIMEOUT_SECONDS = 300

logger = logging.getLogger("splunk.itp")


class UnmaskedCaseSummaryHandler:

    def handle_POST(self, request, investigation_id):
        requester = request.get("user", "unknown")

        try:
            payload = json.loads(request.get("payload", "{}"))

            user = payload.get("user")
            member_firm = payload.get("member_firm")
            maskmap_ids_raw = payload.get("maskmap_ids", "")

            if not user or not member_firm:
                raise Exception("Missing required parameters")

            maskmap_ids = [x.strip() for x in maskmap_ids_raw.split(",") if x.strip()]

            service = self._connect_service_account(request)

            opm_result = self._run_opm(service, user, member_firm)
            maskmap_result = self._run_maskmap(service, maskmap_ids, member_firm)

            logger.info(json.dumps({
                "investigation_id": investigation_id,
                "event": "case_summary",
                "status": "success",
                "requester": requester,
                "user": user,
                "member_firm": member_firm,
                "maskmap_count": len(maskmap_ids)
            }))

            return {
                "status": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({
                    "user_details": opm_result,
                    "maskmap": maskmap_result,
                    "investigation_id": investigation_id
                })
            }

        except Exception as e:
            logger.warning(json.dumps({
                "investigation_id": investigation_id,
                "event": "case_summary",
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

    def _run_opm(self, service, user, member_firm):
        job = service.saved_searches[OPM_SEARCH].dispatch(
            **{
                "args.user": user,
                "args.member_firm": member_firm
            }
        )
        self._wait(job)
        results = job.results(output_mode="json")
        return json.load(results).get("results", [{}])[0]

    # --------------------------------------------------

    def _run_maskmap(self, service, ids, member_firm):
        if not ids:
            return {}

        timestamps = [int(i.split("@@")[0]) for i in ids]
        earliest = min(timestamps)
        latest = max(timestamps) + TIME_OFFSET

        job = service.saved_searches[MASKMAP_SEARCH].dispatch(
            **{
                "args.earliest": earliest,
                "args.latest": latest,
                "args.maskmap_id": " ".join(ids),
                "args.member_firm": member_firm
            }
        )

        self._wait(job)

        results = job.results(output_mode="json")
        reader = json.load(results)

        combined = {}
        if reader.get("results"):
            for value in reader["results"][0].values():
                try:
                    combined.update(json.loads(value))
                except Exception:
                    continue

        return combined

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
