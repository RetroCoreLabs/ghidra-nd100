// Filter box on the instruction-set overview page (isa/index): typing a name or a word hides
// every table row that does not contain it, and every group heading left with no rows.
// Material loads pages without a full reload, so it hooks document$ rather than DOMContentLoaded.
(function () {
  function setup() {
    var box = document.getElementById("isa-filter");
    if (!box || box.dataset.ready) return;
    box.dataset.ready = "1";
    var content = box.closest("article") || document;
    var tables = content.querySelectorAll("table");
    var count = document.getElementById("isa-filter-count");
    function apply() {
      var q = box.value.trim().toLowerCase();
      var shown = 0;
      for (var t = 0; t < tables.length; t++) {
        var rows = tables[t].tBodies[0] ? tables[t].tBodies[0].rows : [];
        var any = 0;
        for (var r = 0; r < rows.length; r++) {
          var hit = !q || rows[r].textContent.toLowerCase().indexOf(q) >= 0;
          rows[r].style.display = hit ? "" : "none";
          if (hit) any++;
        }
        shown += any;
        // hide the group: its heading, source line, note and table
        var wrap = tables[t].closest(".md-typeset__scrollwrap") || tables[t];
        var el = wrap.previousElementSibling;
        wrap.style.display = any ? "" : "none";
        while (el && el.tagName !== "H2") { el.style.display = any ? "" : "none"; el = el.previousElementSibling; }
        if (el) el.style.display = any ? "" : "none";
      }
      if (count) count.textContent = q ? shown + " match" + (shown === 1 ? "" : "es") : "";
    }
    box.addEventListener("input", apply);
    if (location.hash.indexOf("#q=") === 0) { box.value = decodeURIComponent(location.hash.slice(3)); apply(); }
  }
  if (window.document$) window.document$.subscribe(setup); else document.addEventListener("DOMContentLoaded", setup);
})();
