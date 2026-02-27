import json
import time
import logging
import base64
from splunk.rest import simplerequest

UNMASKED_SEARCH = "ITP - Unmasked Activity Report - Template"
SERVICE_REALM = "itp_secure_api"
SERVICE_USERNAME = "svc_itp_backend"

INDEX_PREFIX = "itp_pri_"
SOURCE_PREFIX = "Threat - "
JOB_TIMEOUT_SECONDS = 300
SPLUNK_APP = "itp"

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
            multisearch = self._build_multisearch(pri_ids, member_firm)

            # Get privileged service credentials
            username, password = self._get_service_token(request)

            # Dispatch the saved search using service account
            sid = self._dispatch_saved_search(username, password, UNMASKED_SEARCH, multisearch, maskmap)

            # Wait for job to complete
            self._wait(username, password, sid)

            logger.info(json.dumps({
                "investigation_id": investigation_id,
                "event": "activity_report",
                "status": "success",
                "requester": requester,
                "user": user,
                "member_firm": member_firm,
                "pri_count": len(pri_ids),
                "sid": sid
            }))

            # Fetch CSV results
            results_csv = self._get_results(username, password, sid)

            return {
                "status": 200,
                "headers": {
                    "Content-Type": "text/csv",
                    "Content-Disposition": f'attachment; filename="{user}.csv"'
                },
                "body": results_csv
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

    # --------------------------
    def _get_service_token(self, request):
        """
        Fetch service account credentials from storage/passwords
        """
        token = request["session"]["authtoken"]
        url = f"/servicesNS/nobody/{SPLUNK_APP}/storage/passwords?output_mode=json"
        resp = simplerequest.get(url, headers={"Authorization": f"Bearer {token}"}, json=True)
        if resp.status != 200:
            raise Exception(f"Failed to fetch service passwords: {resp.data}")

        for entry in resp.data.get("entry", []):
            content = entry.get("content", {})
            realm = content.get("realm")
            username = content.get("username")
            password = content.get("password")
            if realm == SERVICE_REALM and username == SERVICE_USERNAME:
                if not password:
                    raise Exception("Service account password not found")
                return username, password

        raise Exception("Privileged service account not found")

    # --------------------------
    def _dispatch_saved_search(self, username, password, search_name, multisearch, maskmap):
        url = f"/servicesNS/nobody/{SPLUNK_APP}/saved/searches/{search_name}/dispatch?output_mode=json"
        data = {"args.multisearch": multisearch, "args.maskmap": json.dumps(maskmap)}
        auth_header = base64.b64encode(f"{username}:{password}".encode()).decode()
        resp = simplerequest.post(url, headers={"Authorization": f"Basic {auth_header}"}, data=data, json=True)
        if resp.status != 201:
            raise Exception(f"Failed to dispatch search: {resp.data}")

        sid = resp.data.get("sid")
        if not sid:
            raise Exception("SID not found in dispatch response")
        return sid

    # --------------------------
    def _wait(self, username, password, sid):
        url = f"/services/search/jobs/{sid}?output_mode=json"
        start = time.time()
        auth_header = base64.b64encode(f"{username}:{password}".encode()).decode()

        while True:
            resp = simplerequest.get(url, headers={"Authorization": f"Basic {auth_header}"}, json=True)
            if resp.status != 200:
                raise Exception(f"Failed to poll job: {resp.data}")

            entries = resp.data.get("entry", [])
            if not entries:
                raise Exception("Job entry not found in poll response")
            dispatch_state = entries[0].get("content", {}).get("dispatchState")
            if dispatch_state in ("DONE", "FAILED", "FAILED_CANCELLED"):
                break

            if time.time() - start > JOB_TIMEOUT_SECONDS:
                raise Exception("Search timeout")

            time.sleep(0.5)

        if dispatch_state != "DONE":
            raise Exception("Search job failed")

    # --------------------------
    def _get_results(self, username, password, sid):
        url = f"/services/search/jobs/{sid}/results?output_mode=csv&count=0"
        auth_header = base64.b64encode(f"{username}:{password}".encode()).decode()
        resp = simplerequest.get(url, headers={"Authorization": f"Basic {auth_header}"})
        if resp.status != 200:
            raise Exception(f"Failed to fetch results: {resp.data}")
        return resp.data

    # --------------------------
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
            searches.append(search)

        if len(searches) == 1:
            return searches[0][1:-1] if searches[0].startswith("[") else searches[0]

        wrapped_searches = [f"[{s}]" for s in searches]
        return "| multisearch " + " ".join(wrapped_searches)
