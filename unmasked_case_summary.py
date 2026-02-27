import json
import time
import logging
import requests

OPM_SEARCH = "ITP - OPM Private Lookup - Template"
MASKMAP_SEARCH = "ITP - Get Mask Map by ID - Template"

SERVICE_REALM = "itp_secure_api"
SERVICE_USERNAME = "svc_itp_unmask"

TIME_OFFSET = 1
JOB_TIMEOUT_SECONDS = 300
SPLUNK_APP = "itp"
SPLUNK_HOST = "https://localhost:8089"

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

            username, password = self._get_service_credentials(request)

            opm_result = self._run_opm(username, password, user, member_firm)
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
                "body": json.dumps({"error": str(e), "investigation_id": investigation_id})
            }

    # --------------------------
    def _get_service_credentials(self, request):
        token = request["session"]["authtoken"]
        url = f"{SPLUNK_HOST}/servicesNS/nobody/{SPLUNK_APP}/storage/passwords?output_mode=json"
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.get(url, headers=headers, verify=False)
        if resp.status_code != 200:
            raise Exception(f"Failed to fetch service credentials: {resp.text}")
        data = resp.json()
        for entry in data.get("entry", []):
            c = entry.get("content", {})
            if c.get("realm") == SERVICE_REALM and c.get("username") == SERVICE_USERNAME:
                password = c.get("password")
                if not password:
                    raise Exception("Privileged account password not found")
                return SERVICE_USERNAME, password
        raise Exception("Privileged service account not found")

    # --------------------------
    def _run_opm(self, username, password, user, member_firm):
        url = f"{SPLUNK_HOST}/servicesNS/nobody/{SPLUNK_APP}/saved/searches/{OPM_SEARCH}/dispatch?output_mode=json"
        postargs = {"args.user": user, "args.member_firm": member_firm}
        resp = requests.post(url, data=postargs, auth=(username, password), verify=False)
        if resp.status_code != 201:
            raise Exception(f"Failed to dispatch OPM search: {resp.text}")
        sid = resp.json().get("sid")
        if not sid:
            raise Exception("SID not returned for OPM search")
        self._wait(username, password, sid)

        url_results = f"{SPLUNK_HOST}/services/search/jobs/{sid}/results?output_mode=json&count=0"
        resp = requests.get(url_results, auth=(username, password), verify=False)
        if resp.status_code != 200:
            raise Exception(f"Failed to fetch OPM results: {resp.text}")
        results = resp.json().get("results", [{}])
        return results[0]

    # --------------------------
    def _run_maskmap(self, username, password, ids, member_firm):
        if not ids:
            return {}
        timestamps = [int(i.split("@@")[0]) for i in ids]
        earliest = min(timestamps)
        latest = max(timestamps) + TIME_OFFSET

        url = f"{SPLUNK_HOST}/servicesNS/nobody/{SPLUNK_APP}/saved/searches/{MASKMAP_SEARCH}/dispatch?output_mode=json"
        postargs = {
            "args.earliest": earliest,
            "args.latest": latest,
            "args.maskmap_id": " ".join(ids),
            "args.member_firm": member_firm
        }
        resp = requests.post(url, data=postargs, auth=(username, password), verify=False)
        if resp.status_code != 201:
            raise Exception(f"Failed to dispatch MaskMap search: {resp.text}")
        sid = resp.json().get("sid")
        if not sid:
            raise Exception("SID not returned for MaskMap search")

        self._wait(username, password, sid)

        url_results = f"{SPLUNK_HOST}/services/search/jobs/{sid}/results?output_mode=json&count=0"
        resp = requests.get(url_results, auth=(username, password), verify=False)
        if resp.status_code != 200:
            raise Exception(f"Failed to fetch MaskMap results: {resp.text}")
        results_list = resp.json().get("results", [])
        combined = {}
        if results_list:
            for v in results_list[0].values():
                try:
                    combined.update(json.loads(v))
                except Exception:
                    continue
        return combined

    # --------------------------
    def _wait(self, username, password, sid):
        url = f"{SPLUNK_HOST}/services/search/jobs/{sid}?output_mode=json"
        start = time.time()
        while True:
            resp = requests.get(url, auth=(username, password), verify=False)
            if resp.status_code != 200:
                raise Exception(f"Failed to poll job: {resp.text}")
            data = resp.json()
            entries = data.get("entry", [])
            if not entries:
                raise Exception("Job entry not found")
            state = entries[0].get("content", {}).get("dispatchState")
            if state in ("DONE", "FAILED", "FAILED_CANCELLED"):
                break
            if time.time() - start > JOB_TIMEOUT_SECONDS:
                raise Exception("Search timeout")
            time.sleep(0.5)
        if state != "DONE":
            raise Exception("Search job failed")
