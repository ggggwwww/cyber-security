const buttons = document.querySelectorAll(".tab-button");
const sections = {
  "ctf-page": document.querySelector(".ctf-page"),
  "making-page": document.querySelector(".making-page"),
  "end-notes": document.querySelector(".end-notes"),
};

buttons.forEach((btn) => {
  btn.addEventListener("click", () => {
    const target = btn.dataset.target;

    buttons.forEach((b) => b.classList.remove("is-active"));
    btn.classList.add("is-active");

    Object.values(sections).forEach((sec) => {
      if (sec) sec.style.display = "none";
    });
    if (sections[target]) sections[target].style.display = "block";
  });
});
