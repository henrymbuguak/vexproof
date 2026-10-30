// Progressive enhancement only: every page works without this file.
// 1. On a scan's progress page, follow the scan and announce each stage, then show the result.
// 2. After a form error, move focus to the summary so screen readers hear it first.
(function () {
  "use strict";

  var summary = document.querySelector("[data-focus]");
  if (summary) {
    summary.focus();
  }

  var page = document.querySelector("[data-job]");
  if (!page || page.getAttribute("data-state") === "failed") {
    return;
  }
  var live = document.getElementById("live");
  var words = {
    done: "Done",
    running: "In progress",
    waiting: "Waiting",
    skipped: "Not needed",
    failed: "Stopped",
  };
  var lastStage = null;

  function render(status) {
    status.stages.forEach(function (row) {
      var item = page.querySelector('[data-stage="' + row.key + '"]');
      if (!item) {
        return;
      }
      item.className = "stage stage-" + row.status;
      item.querySelector(".stage-state").textContent = words[row.status] || row.status;
    });
    var running = status.stages.filter(function (row) {
      return row.status === "running";
    })[0];
    if (running && running.key !== lastStage) {
      lastStage = running.key;
      live.textContent = running.label + ".";
    }
  }

  function poll() {
    fetch("/scans/" + page.getAttribute("data-job") + "/status", {
      headers: { Accept: "application/json" },
    })
      .then(function (response) {
        return response.ok ? response.json() : null;
      })
      .then(function (status) {
        if (!status) {
          return;
        }
        if (status.state === "done" || status.state === "failed") {
          live.textContent =
            status.state === "done" ? "Scan finished. Loading the result." : "The scan stopped.";
          window.location.reload();
          return;
        }
        render(status);
        window.setTimeout(poll, 2000);
      })
      .catch(function () {
        window.setTimeout(poll, 5000);
      });
  }

  window.setTimeout(poll, 1000);
})();
