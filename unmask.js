require([
    'underscore',
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/simplexml/ready!'
], function (_, $, mvc) {

    // ===== Constants =====
    const UI_STATES = {
        NONE: { icon: '', message: '', class: '' },
        LOADING: { icon: 'icon-loading', message: 'Generating report...', class: '' },
        SUCCESS: { icon: 'icon-check-circle', message: 'Done!', class: 'success' },
        ERROR: { icon: 'icon-alert', message: 'Error running report.', class: 'alert-error' }
    };

    const CSS_CLASSES = {
        DISABLED: 'disabled',
        SUCCESS: 'success',
        ERROR: 'alert-error'
    };

    // ===== State =====
    const state = {
        isProcessing: false
    };

    // ===== Service =====
    const service = mvc.createService(); // Uses logged-in user
    const tokensDefault = mvc.Components.get("default", { create: true });
    const tokensSubmitted = mvc.Components.get("submitted");

    const $downloadButton = $('.btn-download-report');
    const $message = $('.message');

    // ===== Utilities =====

    function setToken(name, value) {
        tokensDefault.set(name, value);
        tokensSubmitted.set(name, value);
    }

    function updateUIState(stateKey, customMessage = null) {
        const config = UI_STATES[stateKey];

        $message
            .removeClass([CSS_CLASSES.SUCCESS, CSS_CLASSES.ERROR].join(' '))
            .addClass(config.class);

        $message.find('i').attr('class', config.icon);
        $message.find('span').text(customMessage || config.message);
    }

    function setButtonState(enabled) {
        enabled
            ? $downloadButton.removeClass(CSS_CLASSES.DISABLED)
            : $downloadButton.addClass(CSS_CLASSES.DISABLED);
    }

    // ============================================================
    // CASE SUMMARY
    // Runs automatically on page load
    // ============================================================

    async function fetchSummary() {
        try {

            const payload = {
                investigation_id: tokensDefault.get("investigation_id"),
                user: tokensDefault.get("user"),
                member_firm: tokensDefault.get("member_firm"),
                maskmap_ids: tokensDefault.get("maskmap_id")
            };

            if (!payload.user || !payload.member_firm) {
                throw new Error("Missing required tokens");
            }

            updateUIState('LOADING', 'Loading investigation summary...');

            const response = await service.post(
                "itp/unmasked-case-summary",
                JSON.stringify(payload),
                { headers: { "Content-Type": "application/json" } }
            );

            const data = JSON.parse(response.data);

            setToken('user_details', JSON.stringify(data.user_details || {}));
            setToken('maskmap', JSON.stringify(data.maskmap || {}));

            setButtonState(true);
            updateUIState('NONE');

        } catch (error) {
            console.error("Summary fetch failed:", error);
            updateUIState('ERROR', error.message || 'Failed to load summary');
            setButtonState(false);
        }
    }

    // ============================================================
    // ACTIVITY REPORT
    // ============================================================

    async function generateActivityReport() {

        const payload = {
            investigation_id: tokensDefault.get("investigation_id"),
            user: tokensDefault.get("user"),
            member_firm: tokensDefault.get("member_firm"),
            pri_group_ids: tokensDefault.get("pri_group_id"),
            maskmap: JSON.parse(tokensDefault.get("maskmap") || "{}")
        };

        if (!payload.pri_group_ids) {
            throw new Error("No PRI group IDs found");
        }

        const response = await service.post(
            "itp/unmasked-activity-report",
            JSON.stringify(payload),
            { headers: { "Content-Type": "application/json" } }
        );

        return response.data; // CSV string
    }

    // ============================================================
    // Download Handler
    // ============================================================

    function handleDownloadClick() {

        if (state.isProcessing) return;

        state.isProcessing = true;
        setButtonState(false);
        updateUIState('LOADING');

        generateActivityReport()
            .then(csvData => {

                const user = tokensDefault.get("user") || "report";
                const blob = new Blob([csvData], { type: "text/csv" });
                const url = window.URL.createObjectURL(blob);

                const a = document.createElement("a");
                a.href = url;
                a.download = `${user}.csv`;
                document.body.appendChild(a);
                a.click();
                a.remove();

                updateUIState('SUCCESS');

            })
            .catch(error => {
                console.error("Activity report error:", error);
                updateUIState('ERROR', error.message || 'Failed to generate report');
            })
            .finally(() => {
                state.isProcessing = false;
                setTimeout(() => setButtonState(true), 1000);
            });
    }

    // ============================================================
    // Initialization
    // ============================================================

    async function initialize() {
        try {
            updateUIState('LOADING', 'Loading investigation...');
            setButtonState(false);

            await fetchSummary();  // 🔥 Runs automatically on page ready

            updateUIState('NONE');

        } catch (error) {
            console.error("Initialization failed:", error);
            updateUIState('ERROR', 'Failed to load dashboard');
            setButtonState(false);
        }
    }

    // Attach event
    $downloadButton.on('click', handleDownloadClick);

    // Run immediately when page ready
    initialize();
});
