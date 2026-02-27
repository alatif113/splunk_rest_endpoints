import json
import time
import logging
import splunk.rest.simplerequests as simplerequests

UNMASKED_SEARCH = "ITP - Unmasked Activity Report - Template"

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
            token = request["session"]["authtoken"]

            # Dispatch saved search
            sid = self._dispatch_saved_search(token, UNMASKED_SEARCH, multisearch, maskmap)

            # Wait for search job to complete
            self._wait(token, sid)

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

            # Fetch results in CSV
            results_csv = self._get_results(token, sid)

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

    def _dispatch_saved_search(self, token, search_name, multisearch, maskmap):
        url = f"/servicesNS/nobody/{SPLUNK_APP}/saved/searches/{search_name}/dispatch"
        headers = {"Authorization": f"Bearer {token}"}
        data = {
            "args.multisearch": multisearch,
            "args.maskmap": json.dumps(maskmap)
        }

        resp = simplerequests.post(url, headers=headers, data=data)
        if resp.status != 201:
            raise Exception(f"Failed to dispatch search: {resp.data}")

        return resp.data.get("sid")

    # --------------------------

    def _wait(self, token, sid):
        url = f"/services/search/jobs/{sid}"
        headers = {"Authorization": f"Bearer {token}"}
        start = time.time()

        while True:
            resp = simplerequests.get(url, headers=headers)
            if resp.status != 200:
                raise Exception(f"Failed to poll job: {resp.data}")

            job_info = resp.data
            dispatch_state = job_info.get("entry")[0]["content"]["dispatchState"]

            if dispatch_state in ("DONE", "FAILED", "FAILED_CANCELLED"):
                break

            if time.time() - start > JOB_TIMEOUT_SECONDS:
                raise Exception("Search timeout")

            time.sleep(0.5)

        if dispatch_state != "DONE":
            raise Exception("Search job failed")

    # --------------------------

    def _get_results(self, token, sid):
        url = f"/services/search/jobs/{sid}/results?output_mode=csv&count=0"
        headers = {"Authorization": f"Bearer {token}"}

        resp = simplerequests.get(url, headers=headers)
        if resp.status != 200:
            raise Exception(f"Failed to fetch results: {resp.data}")

        return resp.data

    # --------------------------

    def _build_multisearch(self, pri_ids, firm):
        """
        Build a multisearch string for Splunk.

        Single PRI: returns normal search string.
        Multiple PRIs: returns a proper multisearch string.
        """
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
            # Single search: no multisearch needed
            return searches[0]

        # Multiple searches: combine using multisearch
        wrapped_searches = [f"[{s}]" for s in searches]
        return "| multisearch " + " ".join(wrapped_searches)
