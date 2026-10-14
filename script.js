const messageInput = document.querySelector("#messageInput");
const charCount = document.querySelector("#charCount");
const clearButton = document.querySelector("#clearButton");
const analyzeButton = document.querySelector("#analyzeButton");
const emptyState = document.querySelector("#emptyState");
const loadingState = document.querySelector("#loadingState");
const errorState = document.querySelector("#errorState");
const errorMessage = document.querySelector("#errorMessage");
const resultContent = document.querySelector("#resultContent");

function showState(state) {
    emptyState.hidden = state !== "empty";
    loadingState.hidden = state !== "loading";
    errorState.hidden = state !== "error";
    resultContent.hidden = state !== "result";
}

function showError(message) {
    errorMessage.textContent = message;
    showState("error");
}

function renderResult(data) {
    const riskScore = Number.isFinite(data.risk_score)
        ? `${data.risk_score}% preliminary signal`
        : "Not calculated";
    const uncertainty = Number.isFinite(data.uncertainty)
        ? `${Math.round(data.uncertainty * 100)}% uncertainty`
        : "Uncertainty is unresolved";
    const details = Array.isArray(data.evidence_details)
        ? data.evidence_details
        : [];
    const evidenceList = document.querySelector("#evidenceList");

    document.querySelector("#assessmentText").textContent =
        data.assessment || "Insufficient Evidence";
    document.querySelector("#assessmentDescription").textContent =
        `${riskScore} · ${uncertainty}`;
    document.querySelector("#indicatorCount").textContent =
        String(data.indicator_count ?? details.length);
    document.querySelector("#evidenceStatus").textContent =
        data.risk_level || "Insufficient Evidence";
    document.querySelector("#evidenceBadge").textContent =
        `${details.length} found`;
    document.querySelector("#disclaimer").textContent = data.disclaimer || "";

    evidenceList.replaceChildren();
    if (details.length === 0) {
        const item = document.createElement("li");
        item.className = "no-evidence";
        item.textContent = "No specific warning indicators were detected.";
        evidenceList.append(item);
    } else {
        for (const detail of details) {
            const item = document.createElement("li");
            item.textContent = detail.reason
                ? `${detail.indicator}: ${detail.reason}`
                : detail.indicator;
            evidenceList.append(item);
        }
    }

    showState("result");
}

async function investigateMessage() {
    const text = messageInput.value.trim();
    if (!text) {
        showError("Enter a message before starting the investigation.");
        messageInput.focus();
        return;
    }

    analyzeButton.disabled = true;
    analyzeButton.innerHTML = "<span>⌕</span> Investigating...";
    showState("loading");

    try {
        const response = await fetch("/api/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text })
        });

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.detail || `Server returned status ${response.status}`);
        }
        if (data.error) {
            throw new Error(data.error);
        }

        renderResult(data);
    } catch (error) {
        console.error("TrustGuard analysis error:", error);
        showError(
            error instanceof TypeError
                ? "Could not connect to the analysis service. Check that the app server is running."
                : `Investigation failed: ${error.message}`
        );
    } finally {
        analyzeButton.disabled = false;
        analyzeButton.innerHTML = "<span>⌕</span> Investigate Message";
    }
}

messageInput.addEventListener("input", () => {
    charCount.textContent = `${messageInput.value.length} / 10000 characters`;
});

clearButton.addEventListener("click", () => {
    messageInput.value = "";
    charCount.textContent = "0 / 10000 characters";
    showState("empty");
    messageInput.focus();
});

analyzeButton.addEventListener("click", investigateMessage);