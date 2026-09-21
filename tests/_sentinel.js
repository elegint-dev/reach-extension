// Pins app/lib/platform.js to Sentinel for a test file. Import it FIRST:
// module evaluation follows import order, and platform.js reads the global
// once, when it is first evaluated.
globalThis.REACH_PLATFORM = "sentinel";
