const form = document.querySelector("#cbom-demo-form");
const input = document.querySelector("#domain-input");
const result = document.querySelector("#demo-result");
const resultDomain = document.querySelector("#result-domain");
const resultScore = document.querySelector("#result-score");
const resultSummary = document.querySelector("#result-summary");

function normalizeDomain(value) {
  return value
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .toLowerCase();
}

function isValidDomain(value) {
  return /^(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/.test(value);
}

function previewScore(domain) {
  let total = 0;
  for (const character of domain) {
    total += character.charCodeAt(0);
  }
  return 52 + (total % 18);
}

form.addEventListener("submit", (event) => {
  event.preventDefault();

  const domain = normalizeDomain(input.value);

  if (!isValidDomain(domain)) {
    input.setAttribute("aria-invalid", "true");
    result.hidden = false;
    result.classList.add("invalid");
    resultDomain.textContent = "Invalid domain";
    resultScore.textContent = "--";
    resultSummary.textContent =
      "Enter a public domain like example.com. This educational form does not scan or contact the domain.";
    return;
  }

  input.setAttribute("aria-invalid", "false");
  result.hidden = false;
  result.classList.remove("invalid");
  resultDomain.textContent = domain;
  resultScore.textContent = previewScore(domain);
  resultSummary.textContent =
    "This educational preview shows how Qyrion explains a public TLS CBOM. It did not scan or contact the domain. To generate a real local report, run the scanner command shown below.";
});
