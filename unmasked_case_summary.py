import json
import time
import logging
import base64
from splunk.rest import simplerequest

OPM_SEARCH = "ITP - OPM Private Lookup - Template"
MASKMAP_SEARCH = "ITP - Get Mask Map by ID - Template"

SERVICE_REALM = "itp_secure_api"
SERVICE_USERNAME = "svc_itp_unmask"

TIME_OFFSET = 1
JOB_TIMEOUT_SECONDS = 300
SPLUNK_APP = "itp"

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

            # Get privileged service account credentials
            username, password = self._get_service_token(request)

            # Run OPM search
            opm_result = self._run_opm(username, password, user, member_firm)

            # Run MaskMap search
            maskmap_result = self._run_maskmap(username, password, maskmap_ids, member_firm)

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

    # --------------------------
    def _get_service_token(self, request):
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
    def _run_opm(self, username, password, user, member_firm):
        url = f"/servicesNS/nobody/{SPLUNK_APP}/saved/searches/{OPM_SEARCH}/dispatch?output_mode=json"
        data = {"args.user": user, "args.member_firm": member_firm}
        auth_header = base64.b64encode(f"{username}:{password}".encode()).decode()
        resp = simplerequest.post(url, headers={"Authorization": f"Basic {auth_header}"}, data=data, json=True)
        if resp.status != 201:
            raise Exception(f"Failed to dispatch OPM search: {resp.data}")

        sid = resp.data.get("sid")
        if not sid:
            raise Exception("SID not found for OPM search")

        self._wait(username, password, sid)

        # Fetch JSON results
        url_results = f"/services/search/jobs/{sid}/results?output_mode=json&count=0"
        resp_results = simplerequest.get(url_results, headers={"Authorization": f"Basic {auth_header}"}, json=True)
        if resp_results.status != 200:
            raise Exception(f"Failed to fetch OPM results: {resp_results.data}")

        results = resp_results.data.get("results", [{}])
        return results[0]

    # --------------------------
    def _run_maskmap(self, username, password, ids, member_firm):
        if not ids:
            return {}

        timestamps = [int(i.split("@@")[0]) for i in ids]
        earliest = min(timestamps)
        latest = max(timestamps) + TIME_OFFSET

        url = f"/servicesNS/nobody/{SPLUNK_APP}/saved/searches/{MASKMAP_SEARCH}/dispatch?output_mode=json"
        data = {
            "args.earliest": earliest,
            "args.latest": latest,
            "args.maskmap_id": " ".join(ids),
            "args.member_firm": member_firm
        }
        auth_header = base64.b64encode(f"{username}:{password}".encode()).decode()
        resp = simplerequest.post(url, headers={"Authorization": f"Basic {auth_header}"}, data=data, json=True)
        if resp.status != 201:
            raise Exception(f"Failed to dispatch MaskMap search: {resp.data}")

        sid = resp.data.get("sid")
        if not sid:
            raise Exception("SID not found for MaskMap search")

        self._wait(username, password, sid)

        # Fetch JSON results
        url_results = f"/services/search/jobs/{sid}/results?output_mode=json&count=0"
        resp_results = simplerequest.get(url_results, headers={"Authorization": f"Basic {auth_header}"}, json=True)
        if resp_results.status != 200:
            raise Exception(f"Failed to fetch MaskMap results: {resp_results.data}")

        combined = {}
        results_list = resp_results.data.get("results", [])
        if results_list:
            for value in results_list[0].values():
                try:
                    combined.update(json.loads(value))
                except Exception:
                    continue
        return combined

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
