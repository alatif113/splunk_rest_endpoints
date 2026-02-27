require([
    "jquery",
    "splunkjs/mvc",
    "splunkjs/mvc/utils",
    "splunkjs/mvc/simplexml/ready!"
], function ($, mvc, utils) {

    const defaultTokenModel = mvc.Components.get("default");

    // Create Splunk service bound to current user session
    const service = mvc.createService();


    /* ============================================================
       CASE SUMMARY (JSON RESPONSE)
    ============================================================ */

    function fetchCaseSummary() {

        const payload = {
            investigation_id: defaultTokenModel.get("investigation_id"),
            user: defaultTokenModel.get("user"),
            member_firm: defaultTokenModel.get("member_firm"),
            maskmap_ids: defaultTokenModel.get("maskmap_ids")
        };

        service.post(
            "itp/unmasked-case-summary",
            JSON.stringify(payload),
            {
                headers: {
                    "Content-Type": "application/json"
                }
            }
        ).then(function (response) {

            const data = JSON.parse(response.data);

            console.log("Case summary success:", data);

            defaultTokenModel.set("user_details", JSON.stringify(data.user_details));
            defaultTokenModel.set("maskmap", JSON.stringify(data.maskmap));

        }).catch(function (err) {

            console.error("Case summary failed:", err);
            alert("Case summary failed.");

        });
    }

    $("#case-summary-btn").on("click", fetchCaseSummary);


    /* ============================================================
       ACTIVITY REPORT (CSV DOWNLOAD)
    ============================================================ */

    function fetchActivityReport() {

        const payload = {
            investigation_id: defaultTokenModel.get("investigation_id"),
            user: defaultTokenModel.get("user"),
            member_firm: defaultTokenModel.get("member_firm"),
            pri_group_ids: defaultTokenModel.get("pri_group_ids"),
            maskmap: JSON.parse(defaultTokenModel.get("maskmap") || "{}")
        };

        service.post(
            "itp/unmasked-activity-report",
            JSON.stringify(payload),
            {
                headers: {
                    "Content-Type": "application/json"
                }
            }
        ).then(function (response) {

            // response.data contains CSV string
            const blob = new Blob([response.data], { type: "text/csv" });
            const url = window.URL.createObjectURL(blob);

            const a = document.createElement("a");
            a.href = url;
            a.download = payload.user + ".csv";

            document.body.appendChild(a);
            a.click();
            a.remove();

        }).catch(function (err) {

            console.error("Activity report failed:", err);
            alert("Activity report failed.");

        });
    }

    $("#activity-report-btn").on("click", fetchActivityReport);

});
