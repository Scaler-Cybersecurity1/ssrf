function parseJson(value) {
  try {
    return { ok: true, data: JSON.parse(value || "{}") };
  } catch (err) {
    return { ok: false, error: "Invalid JSON input. Please provide valid JSON." };
  }
}

function timestamp() {
  return new Date().toISOString();
}

function pretty(obj) {
  return JSON.stringify(obj, null, 2);
}

function updateFlag(flagNode, { moduleId, exploited }) {
  const status = exploited ? "PAYLOAD_ACCEPTED" : "REQUEST_PROCESSED";
  const moduleTag = moduleId === "ssrfChallenge" ? "SSRF" : "UNKNOWN";
  flagNode.textContent = `FLAG{SCALER_${moduleTag}_RED_${status}}`;
  flagNode.className = exploited ? "lab-flag alert" : "lab-flag success";
}

function makeTimeline({
  mode,
  service,
  endpoint,
  requestBody,
  backendQuery,
  backendStep,
  outcome,
  impact
}) {
  return [
    `[${timestamp()}] ${service} (${mode.toUpperCase()} MODE)`,
    `Endpoint: ${endpoint}`,
    "",
    "Intercepted Request Body",
    pretty(requestBody),
    "",
    "Built Database Query",
    backendQuery,
    "",
    "Backend Processing",
    backendStep,
    "",
    "Result",
    outcome,
    "",
    "Security Impact",
    impact
  ].join("\n");
}

const handlers = {
  ssrfChallenge: {
    vulnerable(body) {
      const url = String(body.url || "");
      const challengeMatch = url.trim().toLowerCase() === "http://scaler-cybersecurity1.github.io/latest/meta-data/";
      const metadata = /169\.254\.169\.254\/latest\/meta-data/i.test(url);
      const localhost = /localhost|127\.0\.0\.1|0\.0\.0\.0/i.test(url);
      const privateNet = /192\.168\.|10\.|172\.(1[6-9]|2\d|3[0-1])\./i.test(url);
      const fileScheme = /^file:\/\//i.test(url);
      const injected = challengeMatch || metadata || localhost || privateNet || fileScheme;

      return {
        bad: injected,
        text: injected
          ? makeTimeline({
              mode: "vulnerable",
              service: "Media Service",
              endpoint: "POST /api/media/fetch-image",
              requestBody: body,
              backendQuery: `fetch("${url}")`,
              backendStep: "Backend image fetcher requested attacker-controlled URL with no destination allow-list or private address checks.",
              outcome: "200 OK - internal response fetched through server network path.",
              impact: "SSRF succeeds and can expose metadata, localhost admin panels, or private network resources."
            })
          : makeTimeline({
              mode: "vulnerable",
              service: "Media Service",
              endpoint: "POST /api/media/fetch-image",
              requestBody: body,
              backendQuery: `fetch("${url}")`,
              backendStep: "Fetcher called external URL and returned content for thumbnail pipeline.",
              outcome: "200 OK - external asset retrieved.",
              impact: "No obvious SSRF impact in this specific request."
            })
      };
    }
  }
};

const activity = document.getElementById("activity");

document.querySelectorAll(".module").forEach((card) => {
  const id = card.dataset.id;
  const input = card.querySelector(".payload");
  const flagNode = card.querySelector(".lab-flag");
  const runButton = card.querySelector(".action.run");
  const handler = handlers[id];

  runButton.addEventListener("click", () => {
    const parsed = parseJson(input.value);
    if (!parsed.ok) {
      activity.textContent = parsed.error;
      activity.className = "output bad";
      return;
    }

    const result = handler.vulnerable(parsed.data);
    activity.textContent = result.text;
    activity.className = result.bad ? "output bad" : "output warning";
    updateFlag(flagNode, { moduleId: id, exploited: result.bad });
  });
});
