// SafeRecruit AI - LinkedIn Content Script
// Runs on linkedin.com/jobs/* pages to extract job posting data from the DOM.

function extractJobData() {
  const titleEl = document.querySelector("h1") || document.querySelector(".top-card-layout__title");
  const companyEl = document.querySelector(".topcard__org-name-link") || document.querySelector(".topcard__flavor");
  
  // Primary description selectors
  const descriptionEl = document.querySelector(".jobs-description-content__text") || document.querySelector("#job-details");
  
  const title = titleEl ? titleEl.innerText.trim() : "";
  const company = companyEl ? companyEl.innerText.trim() : "";
  let description = descriptionEl ? descriptionEl.innerText.trim() : "";

  // Fallback if primary extraction is empty or too short
  if (!description || description.length < 100) {
    description = document.body.innerText.slice(0, 2000);
  } else {
    // Limit to 2000 characters to reduce noise even if successful
    description = description.slice(0, 2000);
  }

  const combinedText = [
    title ? "Job Title: " + title : "",
    company ? "Company: " + company : "",
    "Description:\n" + description
  ].filter(Boolean).join("\n\n");

  return { text: combinedText };
}

// Listen for messages from the popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "extractJob") {
    const data = extractJobData();
    sendResponse(data);
  }
  return true; // keep the message channel open for async response
});
