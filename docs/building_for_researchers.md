"""
# Notes for Researchers

- To evaluate steganalysis resistance, run statistical tests (chi-square, RS analysis, histogram comparisons) on a large corpus.
- Use the randomized embedding and edge-based modules; tune PRNG seeds and Argon2 params for your threat model.
- When implementing DCT/JPEG embedding, prefer native bindings to libjpeg for correctness.
- Document experiments: carrier types, payload sizes, embedding parameters, and detection results.

Ethics:
- Obtain consent where applicable.
- Use only for permitted research and defensive purposes.
"""
