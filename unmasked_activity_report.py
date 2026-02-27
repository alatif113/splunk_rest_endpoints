import json
import time
import logging
import requests

UNMASKED_SEARCH = "ITP - Unmasked Activity Report - Template"
SERVICE_REALM = "itp_secure_api"
SERVICE_USERNAME = "svc_itp_unmask"

INDEX_PREFIX = "itp_pri_"
SOURCE_PREFIX = "Threat - "
JOB_TIMEOUT_SECONDS = 300
SPLUNK_APP = "itp"
SPLUNK_HOST = "https://localhost:8089"

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

            # Get privileged credentials
            username, password = self._get_service_credentials(request)

            # Dispatch search
            sid = self._dispatch_saved_search(username, password, UNMASKED_SEARCH, multisearch, maskmap)

            # Wait for job completion
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

            # Get results
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
    def _dispatch_saved_search(self, username, password, search_name, multisearch, maskmap):
        url = f"{SPLUNK_HOST}/servicesNS/nobody/{SPLUNK_APP}/saved/searches/{search_name}/dispatch?output_mode=json"
        postargs = {"args.multisearch": multisearch, "args.maskmap": json.dumps(maskmap)}
        resp = requests.post(url, data=postargs, auth=(username, password), verify=False)
        if resp.status_code != 201:
            raise Exception(f"Failed to dispatch search: {resp.text}")
        data = resp.json()
        sid = data.get("sid")
        if not sid:
            raise Exception("SID not returned from dispatch")
        return sid

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

    # --------------------------
    def _get_results(self, username, password, sid):
        url = f"{SPLUNK_HOST}/services/search/jobs/{sid}/results?output_mode=csv&count=0"
        resp = requests.get(url, auth=(username, password), verify=False)
        if resp.status_code != 200:
            raise Exception(f"Failed to fetch results: {resp.text}")
        return resp.text

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
            return searches[0]
        return "| multisearch " + " ".join(f"[{s}]" for s in searches)
