import { useCallback, useEffect, useState } from "react";
import { C } from "./theme";
import Splash from "./components/Splash";
import { api } from "./api";
import { buildCollection } from "./collection";

import DashboardPage from "./pages/DashboardPage";
import TargetsPage from "./pages/TargetsPage";
import HttpPage from "./pages/HttpPage";
import EndpointsPage from "./pages/EndpointsPage";
import JavaScriptPage from "./pages/JavaScriptPage";
import SqliPage from "./pages/SqliPage";
import FindingsPage from "./pages/FindingsPage";
import ReportsPage from "./pages/ReportsPage";

const TABS = [
  { id: "dashboard", label: "Dashboard" },
  { id: "targets", label: "Targets" },
  { id: "http", label: "HTTP Analysis" },
  { id: "endpoints", label: "Endpoint Discovery" },
  { id: "javascript", label: "JavaScript" },
  { id: "sqli", label: "SQLi Test" },
  { id: "findings", label: "Findings" },
  { id: "reports", label: "Reports" },
];

function Page({ id, ctx }) {
  switch (id) {
    case "dashboard":
      return <DashboardPage ctx={ctx} />;

    case "targets":
      return <TargetsPage ctx={ctx} />;

    case "http":
      return <HttpPage ctx={ctx} />;

    case "endpoints":
      return <EndpointsPage ctx={ctx} />;

    case "javascript":
      return <JavaScriptPage ctx={ctx} />;

    case "sqli":
      return <SqliPage ctx={ctx} />;

    case "findings":
      return <FindingsPage ctx={ctx} />;

    case "reports":
      return <ReportsPage ctx={ctx} />;

    default:
      return <DashboardPage ctx={ctx} />;
  }
}

export default function App() {
  // ------------------------------------------------------------
  // APPLICATION STATE
  // ------------------------------------------------------------

  const [showSplash, setShowSplash] = useState(true);
  const [tab, setTab] = useState("dashboard");

  const [targets, setTargets] = useState([]);
  const [activeId, setActiveId] = useState(null);

  const [findings, setFindings] = useState([]);
  const [autoFindings, setAutoFindings] = useState([]);

  const [findingSeed, setFindingSeed] = useState(null);
  const [sqliSeed, setSqliSeed] = useState(null);

  const [scanData, setScanDataState] = useState({});

  const [scanProgress, setScanProgress] = useState([]);
  const [fullScanRunning, setFullScanRunning] = useState(false);

  const [log, setLog] = useState([]);

  const [apiDown, setApiDown] = useState(false);
  const [totalScans, setTotalScans] = useState(0);

  const [time, setTime] = useState(() =>
    new Date().toLocaleTimeString("en-US", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    })
  );

  const [startedAt] = useState(() => Date.now());

  // ------------------------------------------------------------
  // SPLASH
  // ------------------------------------------------------------

  const dismissSplash = useCallback(() => {
    setShowSplash(false);
  }, []);

  // ------------------------------------------------------------
  // CLOCK
  // ------------------------------------------------------------

  useEffect(() => {
    const timer = setInterval(() => {
      setTime(
        new Date().toLocaleTimeString("en-US", {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
          hour12: false,
        })
      );
    }, 1000);

    return () => {
      clearInterval(timer);
    };
  }, []);

  // ------------------------------------------------------------
  // ACTIVITY LOGGER
  // ------------------------------------------------------------

  const pushLog = useCallback((level, message) => {
    const timestamp = new Date().toLocaleTimeString("en-GB", {
      hour12: false,
    });

    setLog((previous) => [
      ...previous.slice(-300),
      {
        level,
        msg: message,
        time: timestamp,
      },
    ]);
  }, []);

  // ------------------------------------------------------------
  // TARGETS
  // ------------------------------------------------------------

  const refreshTargets = useCallback(async () => {
    try {
      const rows = await api.listTargets();

      const safeRows = Array.isArray(rows) ? rows : [];

      setTargets(safeRows);
      setApiDown(false);

      return safeRows;
    } catch (error) {
      console.error("Pent III API error:", error);

      setApiDown(true);

      const message =
        error && error.message
          ? error.message
          : "Unable to reach the backend";

      pushLog(
        "fail",
        "API connection error: " + message
      );

      return [];
    }
  }, [pushLog]);

  // ------------------------------------------------------------
  // INITIAL APPLICATION STARTUP
  // ------------------------------------------------------------

  useEffect(() => {
    let mounted = true;

    const initialize = async () => {
      const rows = await refreshTargets();

      if (!mounted) {
        return;
      }

      if (rows.length > 0) {
        setActiveId((currentId) => {
          if (currentId !== null) {
            return currentId;
          }

          return rows[0].id;
        });
      }

      pushLog(
        "info",
        "PENTIII initialized — connecting to https://pentiii.onrender.com"
      );
    };

    initialize();

    return () => {
      mounted = false;
    };
  }, [refreshTargets, pushLog]);

  // ------------------------------------------------------------
  // ACTIVE TARGET
  // ------------------------------------------------------------

  const activeTarget =
    targets.find((target) => target.id === activeId) || null;

  // ------------------------------------------------------------
  // FINDINGS
  // ------------------------------------------------------------

  const refreshFindings = useCallback(async () => {
    if (!activeId) {
      setFindings([]);
      return;
    }

    try {
      const rows = await api.listFindings(activeId);

      setFindings(
        Array.isArray(rows) ? rows : []
      );
    } catch (error) {
      console.error("Failed to load findings:", error);
      setFindings([]);
    }
  }, [activeId]);

  // ------------------------------------------------------------
  // AUTOMATIC FINDINGS
  // ------------------------------------------------------------

  const refreshAutoFindings = useCallback(async () => {
    if (!activeId) {
      setAutoFindings([]);
      return;
    }

    try {
      const rows = await api.listAutoFindings(activeId);

      setAutoFindings(
        Array.isArray(rows) ? rows : []
      );
    } catch (error) {
      console.error(
        "Failed to load automatic findings:",
        error
      );

      setAutoFindings([]);
    }
  }, [activeId]);

  // ------------------------------------------------------------
  // ACTIVE TARGET DATA REFRESH
  // ------------------------------------------------------------

  useEffect(() => {
    refreshFindings();
    refreshAutoFindings();

    if (!activeId) {
      setTotalScans(0);
      setScanProgress([]);
      return;
    }

    api
      .getScans(activeId)
      .then((scans) => {
        setTotalScans(
          Array.isArray(scans) ? scans.length : 0
        );
      })
      .catch((error) => {
        console.error(
          "Failed to load scan history:",
          error
        );

        setTotalScans(0);
      });

    setScanProgress([]);
  }, [
    activeId,
    refreshFindings,
    refreshAutoFindings,
  ]);

  // ------------------------------------------------------------
  // SCAN DATA
  // ------------------------------------------------------------

  function setScanDataForTarget(
    targetId,
    key,
    value
  ) {
    setScanDataState((previous) => ({
      ...previous,

      [targetId]: {
        ...(previous[targetId] || {}),
        [key]: value,
      },
    }));
  }

  function setScanData(key, value) {
    if (!activeId) {
      return;
    }

    setScanDataForTarget(
      activeId,
      key,
      value
    );
  }

  const currentScanData =
    scanData[activeId] || {};

  // ------------------------------------------------------------
  // SCAN COUNTER
  // ------------------------------------------------------------

  function bumpScans(amount = 1) {
    const safeAmount =
      Number.isFinite(amount) && amount > 0
        ? amount
        : 0;

    setTotalScans(
      (current) => current + safeAmount
    );
  }

  // ------------------------------------------------------------
  // FINDING SEED
  // ------------------------------------------------------------

  function seedFinding(finding) {
    setFindingSeed(finding);
    setTab("findings");
  }

  const clearFindingSeed = useCallback(() => {
    setFindingSeed(null);
  }, []);

  // ------------------------------------------------------------
  // SQLI SEED
  // ------------------------------------------------------------

  function seedSqli(scan) {
    setSqliSeed(scan);
    setTab("sqli");
  }

  const clearSqliSeed = useCallback(() => {
    setSqliSeed(null);
  }, []);

  // ------------------------------------------------------------
  // FULL SCAN
  // ------------------------------------------------------------

  async function runFullScan() {
    if (!activeTarget || fullScanRunning) {
      return;
    }

    const target = activeTarget;
    const targetId = target.id;

    setFullScanRunning(true);

    let stages = [
      {
        stage: "HTTP Analysis",
        status: "Pending",
      },
      {
        stage: "Endpoint Discovery",
        status: "Pending",
      },
      {
        stage: "JavaScript Analysis",
        status: "Pending",
      },
      {
        stage: "Endpoint Collection",
        status: "Pending",
      },
      {
        stage: "SQL Injection Testing",
        status: "Pending",
      },
    ];

    setScanProgress(stages);

    const updateStage = (
      index,
      status,
      detail = null
    ) => {
      stages = stages.map(
        (stage, stageIndex) => {
          if (stageIndex !== index) {
            return stage;
          }

          return {
            ...stage,
            status,
            ...(detail
              ? { detail }
              : {}),
          };
        }
      );

      setScanProgress(stages);
    };

    pushLog(
      "run",
      "Full scan started -> " + target.url
    );

    let scansSaved = 0;

    try {
      // --------------------------------------------------------
      // STAGE 1: HTTP ANALYSIS
      // --------------------------------------------------------

      updateStage(0, "Running");

      const httpResult =
        await api.scanHttp(targetId);

      setScanDataForTarget(
        targetId,
        "http",
        httpResult
      );

      scansSaved += 1;

      const httpOk =
        httpResult &&
        httpResult.ok === true;

      const httpFlags = Array.isArray(
        httpResult?.flags
      )
        ? httpResult.flags.length
        : 0;

      updateStage(
        0,
        httpOk ? "Complete" : "Failed",
        httpOk
          ? "status " +
              httpResult.status_code +
              ", " +
              httpFlags +
              " flag(s)"
          : httpResult?.error ||
              "HTTP analysis failed"
      );

      pushLog(
        httpOk ? "ok" : "fail",
        httpOk
          ? "HTTP analysis: status " +
              httpResult.status_code
          : "HTTP analysis failed: " +
              (httpResult?.error ||
                "Unknown error")
      );

      // --------------------------------------------------------
      // STAGE 2: ENDPOINT DISCOVERY
      // --------------------------------------------------------

      updateStage(1, "Running");

      const endpointResult =
        await api.scanEndpoints(targetId);

      setScanDataForTarget(
        targetId,
        "endpoints",
        endpointResult
      );

      scansSaved += 1;

      const foundEndpoints =
        Array.isArray(
          endpointResult?.found
        )
          ? endpointResult.found
          : [];

      const checkedEndpoints =
        Number.isFinite(
          endpointResult?.checked
        )
          ? endpointResult.checked
          : 0;

      updateStage(
        1,
        "Complete",
        foundEndpoints.length +
          " of " +
          checkedEndpoints +
          " responded"
      );

      pushLog(
        "ok",
        "Endpoint discovery: " +
          foundEndpoints.length +
          " of " +
          checkedEndpoints +
          " responded"
      );

      // --------------------------------------------------------
      // STAGE 3: JAVASCRIPT ANALYSIS
      // --------------------------------------------------------

      updateStage(2, "Running");

      const jsResult =
        await api.scanJs(targetId);

      setScanDataForTarget(
        targetId,
        "js",
        jsResult
      );

      scansSaved += 1;

      const jsOk =
        jsResult &&
        jsResult.ok === true;

      const scriptCount =
        Number.isFinite(
          jsResult?.scripts_found
        )
          ? jsResult.scripts_found
          : 0;

      const jsEndpoints =
        Array.isArray(
          jsResult?.unique_endpoints
        )
          ? jsResult.unique_endpoints
          : [];

      updateStage(
        2,
        jsOk ? "Complete" : "Failed",
        jsOk
          ? scriptCount +
              " script(s)"
          : jsResult?.error ||
              "JavaScript analysis failed"
      );

      pushLog(
        jsOk ? "ok" : "fail",
        jsOk
          ? "JS analysis: " +
              scriptCount +
              " script(s), " +
              jsEndpoints.length +
              " endpoint-like string(s)"
          : "JS analysis failed: " +
              (jsResult?.error ||
                "Unknown error")
      );

      // --------------------------------------------------------
      // STAGE 4: ENDPOINT COLLECTION
      // --------------------------------------------------------

      updateStage(3, "Running");

      const collection =
        buildCollection(
          target.url,
          endpointResult,
          jsOk ? jsResult : null
        );

      const safeCollection =
        collection || {
          endpoints: [],
          total_endpoints: 0,
          parameterized_endpoints: 0,
        };

      const collectedEndpoints =
        Array.isArray(
          safeCollection.endpoints
        )
          ? safeCollection.endpoints
          : [];

      setScanDataForTarget(
        targetId,
        "collection",
        safeCollection
      );

      updateStage(
        3,
        "Complete",
        (safeCollection.parameterized_endpoints ||
          0) +
          " parameterized endpoint(s)"
      );

      pushLog(
        "ok",
        "Endpoint collection: " +
          (safeCollection.total_endpoints ||
            collectedEndpoints.length) +
          " total, " +
          (safeCollection.parameterized_endpoints ||
            0) +
          " parameterized"
      );

      // --------------------------------------------------------
      // STAGE 5: SQL INJECTION TESTING
      // --------------------------------------------------------

      updateStage(4, "Running");

      const parameterizedEndpoints =
        collectedEndpoints.filter(
          (endpoint) =>
            endpoint &&
            endpoint.has_parameters
        );

      if (
        parameterizedEndpoints.length ===
        0
      ) {
        updateStage(
          4,
          "Skipped",
          "no parameterized endpoints found"
        );

        pushLog(
          "info",
          "SQL injection testing skipped - no parameterized endpoints discovered"
        );
      } else {
        const sqliResults = [];

        for (
          const endpoint of parameterizedEndpoints
        ) {
          const parameters =
            Array.isArray(
              endpoint.parameters
            )
              ? endpoint.parameters
              : [];

          for (
            const parameter of parameters
          ) {
            let originalValue = "1";

            try {
              const parsedUrl =
                new URL(endpoint.url);

              const value =
                parsedUrl.searchParams.get(
                  parameter
                );

              if (value !== null) {
                originalValue = value;
              }
            } catch {
              originalValue = "1";
            }

            try {
              const result =
                await api.scanSqliAdvanced(
                  targetId,
                  {
                    url: endpoint.url,
                    parameter,
                    original_value:
                      originalValue,

                    enabled: {
                      error: true,
                      boolean: false,
                      time: false,
                      union: false,
                    },
                  }
                );

              const safeResult =
                result || {};

              sqliResults.push({
                url: endpoint.url,
                parameter,
                ...safeResult,
              });

              scansSaved += 1;

              if (
                safeResult.ok &&
                safeResult.vulnerable
              ) {
                pushLog(
                  "fail",
                  'SQLi: possible injection on "' +
                    parameter +
                    '" at ' +
                    endpoint.url +
                    " (confidence: " +
                    (safeResult.confidence ||
                      "unknown") +
                    ")"
                );
              }
            } catch (error) {
              const errorMessage =
                error &&
                error.message
                  ? error.message
                  : "SQLi request failed";

              sqliResults.push({
                url: endpoint.url,
                parameter,
                ok: false,
                vulnerable: false,
                error: errorMessage,
              });

              pushLog(
                "fail",
                "SQLi test failed for " +
                  parameter +
                  ": " +
                  errorMessage
              );
            }
          }
        }

        setScanDataForTarget(
          targetId,
          "fullScanSqli",
          sqliResults
        );

        const vulnerableCount =
          sqliResults.filter(
            (result) =>
              result &&
              result.ok &&
              result.vulnerable
          ).length;

        updateStage(
          4,
          "Complete",
          sqliResults.length +
            " parameter(s) tested, " +
            vulnerableCount +
            " flagged"
        );

        pushLog(
          vulnerableCount > 0
            ? "fail"
            : "ok",
          "SQL injection testing complete: " +
            sqliResults.length +
            " parameter(s) tested, " +
            vulnerableCount +
            " flagged"
        );
      }

      // --------------------------------------------------------
      // FINISH
      // --------------------------------------------------------

      bumpScans(scansSaved);

      await refreshTargets();
      await refreshFindings();
      await refreshAutoFindings();

      pushLog(
        "ok",
        "Full scan complete for " +
          target.name
      );
    } catch (error) {
      const errorMessage =
        error && error.message
          ? error.message
          : "Unknown full scan error";

      pushLog(
        "fail",
        "Full scan error: " +
          errorMessage
      );

      await refreshAutoFindings();
    } finally {
      setFullScanRunning(false);
    }
  }

  // ------------------------------------------------------------
  // DASHBOARD METRICS
  // ------------------------------------------------------------

  const sessionMinutes = Math.floor(
    (Date.now() - startedAt) / 60000
  );

  const findingsHigh =
    findings.filter(
      (finding) =>
        finding.severity === "High"
    ).length;

  const findingsMed =
    findings.filter(
      (finding) =>
        finding.severity === "Medium"
    ).length;

  const findingsLow =
    findings.filter(
      (finding) =>
        finding.severity === "Low"
    ).length;

  // ------------------------------------------------------------
  // PAGE CONTEXT
  // ------------------------------------------------------------

  const baseCtx = {
    targets,

    activeId,
    activeTarget,
    setActiveId,

    findings,
    refreshFindings,

    findingSeed,
    clearFindingSeed,
    seedFinding,

    autoFindings,
    refreshAutoFindings,

    sqliSeed,
    clearSqliSeed,
    seedSqli,

    api,
    apiDown,

    totalScans,
    refreshTargets,
    bumpScans,

    scanData: currentScanData,
    setScanData,

    runFullScan,
    scanProgress,
    fullScanRunning,

    setFullScanRunning,
    setScanProgress,

    showAddTarget: () => {
      setTab("targets");
    },
  };

  const pageCtx = {
    ...baseCtx,
    log: pushLog,
  };

  const dashboardCtx = {
    ...baseCtx,
    log,
  };

  // ------------------------------------------------------------
  // RENDER
  // ------------------------------------------------------------

  return (
    <>
      {showSplash && (
        <Splash
          duration={2000}
          onDone={dismissSplash}
        />
      )}

      <div
        style={{
          display: "flex",
          flexDirection: "column",
          height: "100vh",
          background: C.bg,
          overflow: "hidden",
          fontFamily:
            "var(--font-display)",
        }}
      >
        {/* ====================================================
            TOP BAR
        ==================================================== */}

        <div
          style={{
            display: "flex",
            alignItems: "center",
            height: 34,
            background: C.panel,
            borderBottom:
              "1px solid " + C.border,
            flexShrink: 0,
          }}
        >
          {/* BRAND */}

          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              padding: "0 14px",
              borderRight:
                "1px solid " + C.border,
              height: "100%",
            }}
          >
            <img
              src="/logo.png"
              alt="PENTIII"
              style={{
                width: 22,
                height: 22,
                objectFit: "contain",
                display: "block",
              }}
            />

            <span
              style={{
                fontSize: 12,
                fontWeight: 700,
                color: C.fg,
                letterSpacing: "0.06em",
              }}
            >
              PENTIII
            </span>

            <span
              style={{
                fontSize: 10,
                color: C.fgDim,
                letterSpacing: "0.04em",
              }}
            >
              v1.0
            </span>
          </div>

          {/* TARGET SELECTOR */}

          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              padding: "0 14px",
              borderRight:
                "1px solid " + C.border,
              height: "100%",
            }}
          >
            <span
              style={{
                fontSize: 11,
                color: C.fgDim,
              }}
            >
              Target
            </span>

            <select
              value={activeId || ""}
              onChange={(event) => {
                const value =
                  event.target.value;

                setActiveId(
                  value
                    ? Number(value)
                    : null
                );
              }}
              aria-label="Active target"
              style={{
                maxWidth: 230,
                background: "transparent",
                border: "none",
                color: C.fgMid,
                fontSize: 11.5,
                fontFamily:
                  "var(--font-mono)",
                outline: "none",
              }}
            >
              {targets.length === 0 && (
                <option value="">
                  none selected
                </option>
              )}

              {targets.map((target) => (
                <option
                  key={target.id}
                  value={target.id}
                >
                  {target.name}
                </option>
              ))}
            </select>
          </div>

          <div
            style={{
              flex: 1,
            }}
          />

          {/* STATUS */}

          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              padding: "0 14px",
              height: "100%",
            }}
          >
            <div
              className={
                apiDown
                  ? ""
                  : "pulse-dot"
              }
              style={{
                width: 6,
                height: 6,
                borderRadius: "50%",
                background: apiDown
                  ? C.critical
                  : C.accent,
              }}
            />

            <span
              style={{
                fontSize: 11,
                color: C.fgDim,
              }}
            >
              {apiDown
                ? "backend unreachable"
                : activeTarget
                ? activeTarget.url +
                  " · active"
                : "no target"}
            </span>

            <span
              style={{
                fontSize: 11,
                color: C.fgDim,
                fontFamily:
                  "var(--font-mono)",
                borderLeft:
                  "1px solid " +
                  C.border,
                paddingLeft: 10,
              }}
            >
              {time}
            </span>

            <span
              style={{
                fontSize: 11,
                color: C.medium,
                borderLeft:
                  "1px solid " +
                  C.border,
                paddingLeft: 10,
              }}
            >
              {findings.length} findings
            </span>
          </div>
        </div>

        {/* ====================================================
            NAVIGATION
        ==================================================== */}

        <div
          className="scrollbar-thin"
          style={{
            display: "flex",
            alignItems: "stretch",
            height: 32,
            background: C.panelB,
            borderBottom:
              "1px solid " + C.border,
            flexShrink: 0,
            overflowX: "auto",
          }}
        >
          {TABS.map((item) => {
            const selected =
              tab === item.id;

            return (
              <button
                key={item.id}
                onClick={() => {
                  setTab(item.id);
                }}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                  padding: "0 16px",
                  border: "none",
                  cursor: "pointer",
                  fontFamily: "inherit",
                  fontSize: 12,
                  whiteSpace: "nowrap",
                  background: selected
                    ? C.panelC
                    : "transparent",
                  color: selected
                    ? C.fg
                    : C.fgMid,
                  borderBottom: selected
                    ? "2px solid " +
                      C.accent
                    : "2px solid transparent",
                  borderRight:
                    "1px solid " +
                    C.border,
                  fontWeight: selected
                    ? 600
                    : 400,
                }}
              >
                {item.label}

                {item.id ===
                  "findings" &&
                  findings.length > 0 && (
                    <span
                      style={{
                        fontSize: 10,
                        fontWeight: 700,
                        color:
                          C.critical,
                        background:
                          "rgba(224,85,85,0.12)",
                        borderRadius: 3,
                        padding:
                          "1px 5px",
                      }}
                    >
                      {findings.length}
                    </span>
                  )}
              </button>
            );
          })}
        </div>

        {/* ====================================================
            API STATUS BANNER
        ==================================================== */}

        {apiDown && (
          <div
            style={{
              padding: "6px 14px",
              background:
                "rgba(224,85,85,0.1)",
              borderBottom:
                "1px solid rgba(224,85,85,0.3)",
              color: C.critical,
              fontSize: 11,
              fontFamily:
                "var(--font-mono)",
            }}
          >
            Can't reach the Pent III API at{" "}
            <strong>
              https://pentiii.onrender.com
            </strong>
            . Check the backend status,
            API key, and CORS configuration.
          </div>
        )}

        {/* ====================================================
            MAIN CONTENT
        ==================================================== */}

        <div
          className="scrollbar-thin"
          style={{
            display: "flex",
            flex: 1,
            overflow: "auto",
            minHeight: 0,
          }}
        >
          <Page
            id={tab}
            ctx={
              tab === "dashboard"
                ? dashboardCtx
                : pageCtx
            }
          />
        </div>

        {/* ====================================================
            STATUS BAR
        ==================================================== */}

        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 0,
            height: 22,
            background: C.panelB,
            borderTop:
              "1px solid " + C.border,
            flexShrink: 0,
          }}
        >
          {[
            activeTarget
              ? activeTarget.url
              : "no target",

            "Session: " +
              sessionMinutes +
              "m",

            "Scans: " +
              totalScans,

            "Findings: " +
              findings.length +
              " (" +
              findingsHigh +
              "H · " +
              findingsMed +
              "M · " +
              findingsLow +
              "L)",

            "Mode: Authorized assessment",
          ].map((text, index) => (
            <span
              key={index}
              style={{
                fontSize: 10.5,
                color: C.fgDim,
                padding: "0 10px",
                borderRight:
                  "1px solid " +
                  C.border,
                fontFamily:
                  "var(--font-mono)",
                height: "100%",
                display: "flex",
                alignItems: "center",
              }}
            >
              {text}
            </span>
          ))}

          <div
            style={{
              flex: 1,
            }}
          />

          <span
            style={{
              fontSize: 10.5,
              color: apiDown
                ? C.critical
                : C.fgDim,
              padding: "0 10px",
              fontFamily:
                "var(--font-mono)",
              borderLeft:
                "1px solid " +
                C.border,
              height: "100%",
              display: "flex",
              alignItems: "center",
            }}
          >
            {apiDown
              ? "Offline"
              : "Ready"}
          </span>
        </div>
      </div>
    </>
  );
}
