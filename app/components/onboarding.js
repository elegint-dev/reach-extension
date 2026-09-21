// onboarding card: the first-install "what to enable and why" card on the
// bare catalogue start page (app/views/start.js). app/lib/onboarding.js
// owns when it shows; this only turns cardModel() into nodes and wires
// the dismiss click.
//
//   onboardingCard()   → a <section>, hidden when onboarding.shouldShow() is false

import { h } from "./h.js";
import * as onboarding from "../lib/onboarding.js";

export function onboardingCard() {
  const model = onboarding.cardModel();
  const el = h(
    "section",
    { class: "r-onboard", hidden: !model.show },
    h(
      "button",
      {
        type: "button",
        class: "r-onboard__dismiss",
        "aria-label": "Dismiss this card",
        onClick: () => {
          onboarding.dismiss();
          el.hidden = true; // the storage write is async; the click hides it now
        },
      },
      "×",
    ),
    h("p", { class: "r-onboard__line" }, model.line),
    h(
      "ol",
      { class: "r-onboard__steps" },
      model.steps.map((s) => h("li", null, s)),
    ),
    h("p", { class: "r-onboard__note" }, model.note),
  );
  return el;
}

export default onboardingCard;
