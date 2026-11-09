# arXiv source bundles (prepared, NOT uploaded)

Ready-to-submit arXiv source bundles built from the RIBCi–CYTED 2026
camera-ready sources:

- `paper1-camera-ready.arxiv.tar.gz` — Paper 1 (detection)
- `paper2-camera-ready.arxiv.tar.gz` — Paper 2 (remediation)

Each contains the camera-ready `.tex` + `.bbl` + `figs/` (so arXiv compiles
without a `.bib`). Rebuild with:

```bash
cd paper/ribci-cyted-2026
for p in paper1-camera-ready paper2-camera-ready; do
  tar -czf "arxiv/$p.arxiv.tar.gz" "$p.tex" "$p.bbl" \
    figs/fig1.pdf figs/fig2.pdf figs/fig_validators.pdf figs/fig_validators.png
done
```

**Not uploaded.** Posting preprints to arXiv depends on the RIBCi–CYTED /
Edições CEOS.PP publisher policy — confirm with the Editing Lab before posting.
Submission metadata (title, authors, subjects, comments, license) is in
`paper/ARXIV_SUBMISSION.md`. The `.tar.gz` bundles are build artifacts
(git-ignored); regenerate them with the command above.
