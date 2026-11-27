# Project governance / 项目治理

LYL-Z maintains the repository, triages contributions and makes release
decisions. Repository history and pull requests record contributions and
technical decisions. [CODEOWNERS](.github/CODEOWNERS) routes review of changes
to authorization, attribution, distribution and release infrastructure.

## Review and releases

Use a pull request for changes that affect shared code. The description should
point to the exact tested commit, relevant automated checks and remaining
limitations. Review permissions, upstream rights and the actual package
contents where applicable. A Stable release follows the evidence and approval
process in the [distribution guide](docs/v24/distribution.md).

All contributors should be able to explain the origin and license of their
changes. Contributors may use `git commit -s` if they can make the
[Developer Certificate of Origin](https://developercertificate.org/)
declaration. Sign-off is voluntary at present. Third-party permissions and
source attribution are reviewed separately.

## Security practices

- Use [OpenSSF Scorecard](https://scorecard.dev/) to assess repository and
  supply-chain practices when the result can be tied to the repository and
  assessment date. No score is claimed here.
- Use the [OpenSSF Best Practices criteria](https://www.bestpractices.dev/en)
  for self-assessment. A badge would require a completed public assessment.
- Use [OSPS Baseline](https://baseline.openssf.org/) v2026.08.28 as a reference.
  Current evidence includes a security policy, protected development checks
  and candidate package checks. An independent production approval path and
  a complete control-by-control assessment remain open.

维护者负责合并和发行决策。高风险变更应说明精确提交、测试证据、授权范围
和来源。普通支持、安全报告及行为规范分别见 [SUPPORT.md](SUPPORT.md)、
[SECURITY.md](SECURITY.md) 和 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。
