import json
import logging
from splunk.persistconn.application import PersistentServerConnectionApplication

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "handlers"))

# Now imports work
from case_summary import UnmaskedCaseSummaryHandler
from activity_report import UnmaskedActivityReportHandler

logger = logging.getLogger("splunk.itp")
logger.setLevel(logging.INFO)


class ItpApiApp(PersistentServerConnectionApplication):

    def handle(self, request):
        try:
            path = request.path.lower()
            payload = json.loads(request.get("payload", "{}"))
            investigation_id = payload.get("investigation_id", "unknown")

            if path.endswith("/unmasked-case-summary"):
                handler = UnmaskedCaseSummaryHandler()
                return handler.handle_POST(request, investigation_id)

            elif path.endswith("/unmasked-activity-report"):
                handler = UnmaskedActivityReportHandler()
                return handler.handle_POST(request, investigation_id)

            else:
                return {
                    "status": 404,
                    "headers": {"Content-Type": "application/json"},
                    "body": json.dumps({
                        "error": "Endpoint not found",
                        "investigation_id": investigation_id
                    })
                }

        except Exception as e:
            logger.exception("PSC routing failure")
            return {
                "status": 500,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({
                    "error": str(e),
                    "investigation_id": payload.get("investigation_id", "unknown")
                })
            }
