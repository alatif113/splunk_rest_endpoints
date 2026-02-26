require([
    'underscore',
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/simplexml/ready!'
], function (_, $, mvc) {

    // ===== Constants =====
    const SEARCH_NAMES = {
        MASKMAP: "ITP - Get Mask Map by ID - Template",
        OPM: "ITP - OPM Private Lookup - Template",
        UNMASKED_ACTIVITY: "ITP - Unmasked Activity Report - Template"
    };
    
    const UI_STATES = {
        NONE: { icon: '', message: '', class: '' },
        LOADING: { icon: 'icon-loading', message: 'Generating report...', class: '' },
        SUCCESS: { icon: 'icon-check-circle', message: 'Done!', class: 'success' },
        ERROR: { icon: 'icon-alert', message: 'Error running report.', class: 'alert-error' }
    };

    const AUTH_TOKEN = "eyJraWQiOiJzcGx1bmsuc2VjcmV0IiwiYWxnIjoiSFM1MTIiLCJ2ZXIiOiJ2MiIsInR0eXAiOiJzdGF0aWMifQ.eyJpc3MiOiJhZG1pbiBmcm9tIGF3MDg3OGwwMDEiLCJzdWIiOiJhZG1pbiIsImF1ZCI6IkFkdmlzb3J5IiwiaWRwIjoiU3BsdW5rIiwianRpIjoiYjkwN2NlZTZiNDhjMjQ0ODA5ZDgwZjM0OTFkNGI3MmFlN2IyM2EzMTdmYjg4ZDNkNGI1ODNkYjIxNWIxYjM5ZiIsImlhdCI6MTc3MjAzMTM2MSwiZXhwIjoxNzc0NjIzMzYxLCJuYnIiOjE3NzIwMzEzNjF9.PQTF4FtRIuJSg5JAhe_vEZd9n-37JA-063KEjf341dJ_Fy6mRc2cq6-JpZzjwMJeEI-MlVZe17rZ3HfRPDnXJg"
    const TIME_OFFSET = 1;
    const INDEX_PREFIX = "itp_pri_";
    const SOURCE_PREFIX = "Threat - ";
    const MACRO_PREFIX = "itp_masked_fields_";
    const CSS_CLASSES = {
        DISABLED: 'disabled',
        SUCCESS: 'success',
        ERROR: 'alert-error'
    };

    // ===== State Management =====
    const state = {
        isProcessing: false,
        savedSearches: null,
        currentJob: null
    };

    // ===== Service & Token Initialization =====
    const privilegedService = mvc.createService({ sessionKey: AUTH_TOKEN });
    const tokensDefault = mvc.Components.get("default", { create: true });
    const tokensSubmitted = mvc.Components.get("submitted");
    const $downloadButton = $('.btn-download-report');
    const $message = $('.message');

    // ===== Utility Functions =====

    /**
     * Calculates latest time with offset
     * @param {number} earliestTime - The earliest time in epoch seconds
     * @returns {number} - Latest time with offset applied
     */
    function calculateLatestTime(earliestTime) {
        return earliestTime + TIME_OFFSET;
    }

    /**
     * Calculates min and max time from maskmap IDs
     * @param {Array<string>} maskmapIds 
     * @returns {{minTime: number, maxTime: number}}
     */
    function getTimeRange(maskmapIds) {
        if (!maskmapIds?.length) {
            throw new Error("No maskmap IDs provided for time range calculation");
        }

        const times = maskmapIds.map(id => {
            const parts = String(id).split("@@");
            const timeStr = parts[0];
            const time = parseInt(timeStr, 10);

            if (isNaN(time)) {
                throw new Error(`Invalid timestamp in maskmap ID: ${id}`);
            }

            return time;
        });

        return {
            minTime: Math.min(...times),
            maxTime: calculateLatestTime(Math.max(...times))
        };
    }

    /**
     * Combines multiple JSON strings into a single object
     * @param {Array<string>} jsonStringList 
     * @returns {Object}
     */
    function combineJSONStrings(jsonStringList) {
        const combined = {};
        const errors = [];

        for (const [index, jsonString] of jsonStringList.entries()) {
            try {
                const obj = JSON.parse(jsonString);
                Object.assign(combined, obj);
            } catch (error) {
                errors.push({ index, jsonString, error: error.message });
                console.error(`Failed to parse JSON at index ${index}:`, error);
            }
        }

        if (errors.length > 0) {
            console.warn(`Failed to parse ${errors.length}/${jsonStringList.length} JSON strings`, errors);
        }

        return combined;
    }

    /**
     * Sets a token in both default and submitted token models
     */
    function setToken(name, value) {
        tokensDefault.set(name, value);
        tokensSubmitted.set(name, value);
    }

    /**
     * Updates UI state based on predefined states
     */
    function updateUIState(stateKey, customMessage = null) {
        const config = UI_STATES[stateKey];

        if (!config) {
            console.error(`Unknown UI state: ${stateKey}`);
            return;
        }

        $message
            .removeClass([CSS_CLASSES.SUCCESS, CSS_CLASSES.ERROR].join(' '))
            .addClass(config.class);
        
        $message.find('i').attr('class', config.icon);
        $message.find('span').text(customMessage || config.message);
    }

    /**
     * Enables or disables the download button
     */
    function setButtonState(enabled) {
        if (enabled) {
            $downloadButton.removeClass(CSS_CLASSES.DISABLED);
        } else {
            $downloadButton.addClass(CSS_CLASSES.DISABLED);
        }
    }

    // ===== Promisified Splunk SDK Functions =====

    async function fetchSavedSearches() {
        return new Promise((resolve, reject) => {
            const savedSearches = privilegedService.savedSearches();
            savedSearches.fetch((err, resource) => {
                if (err) {
                    reject(new Error(`Failed to fetch saved searches: ${err.message || err}`));
                } else {
                    resolve(resource);
                }
            });
        });
    }

    async function dispatchSavedSearch(savedSearch, params) {
        return new Promise((resolve, reject) => {
            savedSearch.dispatch(params, (err, job) => {
                if (err) {
                    reject(new Error(`Failed to dispatch search: ${err.message || err}`));
                } else {
                    resolve(job);
                }
            });
        });
    }

    async function trackJob(job, onProgress = null) {
        return new Promise((resolve, reject) => {
            job.track({}, {
                progress: (job) => {
                    if (onProgress) {
                        const props = job.properties();
                        onProgress(props);
                    }
                },
                done: (job) => resolve(job),
                failed: (job) => {
                    reject(new Error(`Job failed: ${job.sid}`));
                },
                error: (error) => {
                    reject(new Error(`Job tracking error: ${error.message || error}`));
                }
            });
        });
    }

    async function getJobResults(job) {
        return new Promise((resolve, reject) => {
            job.results({}, (err, results) => {
                if (err) {
                    reject(new Error(`Failed to get job results: ${err.message || err}`));
                } else {
                    resolve(results);
                }
            });
        });
    }

    // ===== Main OPM Processing =====

    async function processOPM() {
        try {
            const memberFirm = tokensDefault.get("member_firm");
            
            if (!memberFirm) {
                throw new Error("Member firm not set");
            }

            const searchName = SEARCH_NAMES.OPM

            const opmPrivateSearch = state.savedSearches.item(searchName);

            if (!opmPrivateSearch) {
                throw new Error(`Saved search "${searchName}" not found`);
            }

            const user = tokensDefault.get("user");
            const member_firm = tokensDefault.get("member_firm");

            if (!user) {
                throw new Error("User not set");
            }

            if (!member_firm) {
                throw new Error("Member firm not set");
            }

            const params = { 
                "args.user": user,
                "args.member_firm": member_firm
            };

            console.log(`Dispatching "${searchName}" with params:`, params);
            const opmPrivateJob = await dispatchSavedSearch(opmPrivateSearch, params);
            await trackJob(opmPrivateJob);

            const results = await getJobResults(opmPrivateJob);
            const OPMJson = results.rows?.[0]?.[0];

            if (OPMJson == null || OPMJson === '') {
                console.warn("No OPM data returned from search");
                setToken('user_details', JSON.stringify({}));
                return;
            }

            setToken('user_details', JSON.stringify(OPMJson));

        } catch (error) {
            console.error("Error searching OPM Private Lookup:", error);
            setToken('user_details', JSON.stringify({}));
            throw error;
        }
    }

    // ===== Main Mask Map Processing =====

    async function processMaskMap() {
        try {
            const maskmapIdsRaw = tokensDefault.get("maskmap_id");

            if (!maskmapIdsRaw) {
                console.warn("No maskmap IDs found. Setting empty mask map.");
                setToken('maskmap', JSON.stringify({}));
                return;
            }

            const maskmapIds = maskmapIdsRaw.split(",").map(id => id.trim()).filter(Boolean);

            if (maskmapIds.length === 0) {
                console.warn("No valid maskmap IDs after parsing");
                setToken('maskmap', JSON.stringify({}));
                return;
            }

            console.log(`Processing ${maskmapIds.length} maskmap ID(s):`, maskmapIds);

            const { minTime, maxTime } = getTimeRange(maskmapIds);
            const maskMapSearch = state.savedSearches.item(SEARCH_NAMES.MASKMAP);

            if (!maskMapSearch) {
                throw new Error(`Saved search "${SEARCH_NAMES.MASKMAP}" not found`);
            }

            const params = {
                "args.earliest": minTime,
                "args.latest": maxTime,
                "args.maskmap_id": maskmapIds.join(" "),
                "args.member_firm": tokensDefault.get("member_firm")
            };

            console.log("Dispatching maskmap search with params:", params);
            const maskMapJob = await dispatchSavedSearch(maskMapSearch, params);
            await trackJob(maskMapJob);

            const results = await getJobResults(maskMapJob);
            const rawMaskMapList = results.rows?.[0]?.[0];

            if (rawMaskMapList == null || rawMaskMapList === '') {
                console.warn("No mask map data returned from search");
                setToken('maskmap', JSON.stringify({}));
                return;
            }

            // Normalize to array
            const maskMapList = Array.isArray(rawMaskMapList) ? rawMaskMapList : [rawMaskMapList];

            const combined = combineJSONStrings(maskMapList);
            console.log("Combined mask map:", combined);
            
            // Fixed: removed double stringify
            setToken('maskmap', JSON.stringify(JSON.stringify(combined)));

            setButtonState(true);

        } catch (error) {
            console.error("Error processing mask map:", error);
            setToken('maskmap', JSON.stringify({}));
            throw error;
        }
    }

    // ===== Activity Report Generation =====

    async function generateActivityReport() {
        const memberFirm = tokensDefault.get("member_firm");
        
        if (!memberFirm) {
            throw new Error("Member firm not set");
        }

        const priGroupIdsRaw = tokensDefault.get("pri_group_id");

        if (!priGroupIdsRaw) {
            throw new Error("No PRI group IDs found");
        }

        const priGroupIds = priGroupIdsRaw.split(",").map(id => id.trim()).filter(Boolean);

        // Build base search queries
        const searches = priGroupIds.map(priGroupId => {
            const parts = priGroupId.split("@@");
            
            if (parts.length !== 3) {
                console.error(`Invalid PRI group ID format (expected 3 parts): ${priGroupId}`);
                return null;
            }

            const [time, priName, userValue] = parts;
            const earliestTime = parseInt(time, 10);

            if (isNaN(earliestTime)) {
                console.error(`Invalid timestamp in PRI group ID: ${priGroupId}`);
                return null;
            }

            const latestTime = calculateLatestTime(earliestTime);

            return `search index=${INDEX_PREFIX}${memberFirm} earliest=${earliestTime} latest=${latestTime} source="${SOURCE_PREFIX}${priName}*" user=${userValue}`;
        }).filter(Boolean);

        if (searches.length === 0) {
            throw new Error("No valid PRI group IDs to process");
        }

        // Build multisearch query
        const multisearch = searches.length > 1 
            ? `| multisearch ${searches.map(s => `[${s}]`).join(" ")}`
            : searches[0];

        const activityReportSearch = state.savedSearches.item(SEARCH_NAMES.UNMASKED_ACTIVITY);

        if (!activityReportSearch) {
            throw new Error(`Saved search "${SEARCH_NAMES.UNMASKED_ACTIVITY}" not found`);
        }

        const params = {
            "args.multisearch": multisearch,
            "args.itp_masked_fields_macro": `\`${MACRO_PREFIX}${memberFirm.toLowerCase()}\``,
            "args.maskmap": tokensDefault.get("maskmap")
        };

        console.log("Dispatching activity report with params:", params);
        const activityReportJob = await dispatchSavedSearch(activityReportSearch, params);
        
        // Store job reference for potential cancellation
        state.currentJob = activityReportJob;

        await trackJob(activityReportJob, (props) => {
            // Optional: update progress
            console.log(`Job progress: ${props.doneProgress * 100}%`);
        });

        const jobState = activityReportJob?.properties()?.dispatchState;
        if (jobState === "FAILED") {
            throw new Error("Activity report job failed");
        }

        return activityReportJob;
    }

    // ===== Event Handlers =====

    function handleDownloadClick() {
        // Prevent concurrent executions
        if (state.isProcessing) {
            console.log("Download already in progress");
            return;
        }

        state.isProcessing = true;
        setButtonState(false);
        updateUIState('LOADING');

        generateActivityReport()
            .then(job => {
                const user = tokensDefault.get("user");

                if (!user) {
                    throw new Error("User token not set");
                }

                // Success state
                updateUIState('SUCCESS');

                // Trigger download
                const downloadUrl = `/api/search/jobs/${job.sid}/results?outputMode=csv&isDownload=true&filename=${encodeURIComponent(user)}.csv&count=0`;
                window.location.href = downloadUrl;
            })
            .catch(error => {
                console.error("Error generating activity report:", error);
                updateUIState('ERROR', error.message || 'Failed to generate report');
            })
            .finally(() => {
                state.isProcessing = false;
                state.currentJob = null;
                // Re-enable after a short delay to prevent accidental double-clicks
                setTimeout(() => setButtonState(true), 1000);
            });
    }

    // ===== Initialization =====

    async function initialize() {
        try {
            console.log("Initializing dashboard...");
            updateUIState('LOADING', 'Loading configuration...');

            // Fetch saved searches first
            state.savedSearches = await fetchSavedSearches();
            console.log("Saved searches loaded");

            // Process OPM and mask map in parallel
            await Promise.allSettled([
                processOPM().catch(error => {
                    console.error("OPM processing failed:", error);
                    // Don't block initialization on OPM failure
                }),
                processMaskMap()
            ]);

            console.log("Initialization complete");
            updateUIState('NONE');

        } catch (error) {
            console.error("Failed to initialize dashboard:", error);
            updateUIState('ERROR', 'Failed to load dashboard configuration');
            setButtonState(false);
        }
    }

    // Attach event handler
    $downloadButton.on('click', handleDownloadClick);

    // Start initialization
    initialize();
});
