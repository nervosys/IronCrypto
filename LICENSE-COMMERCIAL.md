# Commercial License for IronCrypto

Copyright (C) 2024-2026 NERVOSYS. All rights reserved.

## Dual Licensing

IronCrypto is available under two licensing options:

### 1. GNU Affero General Public License v3 (AGPL-3.0-or-later)

The default license for IronCrypto is the **GNU Affero General Public License v3**. Under this license:

- You may freely use, copy, modify, and distribute the software.
- If you modify the software and make it available over a network (e.g., as a web service), you **must** make the complete source code of your modified version available to users of that service.
- Any derivative works must also be licensed under the AGPL v3.
- Full text: [LICENSE](LICENSE)

Note that for a cryptography library the network clause has real reach: linking IronCrypto into a service that terminates TLS, signs tokens, or encrypts customer data makes that service a derivative work, and the AGPL's source-disclosure obligation applies to it.

### 2. Commercial License

If the AGPL requirements are incompatible with your use case — for example, if you want to:

- Integrate IronCrypto into proprietary/closed-source software
- Embed it in a shipped product, firmware image, or hardware device
- Distribute IronCrypto without disclosing your source code
- Offer IronCrypto as part of a hosted/SaaS service without AGPL obligations
- Use the software under terms that do not require network-use disclosure
- Receive dedicated support, warranty, or indemnification

Then a **commercial license** is available from NERVOSYS.

## Obtaining a Commercial License

For commercial licensing inquiries, please contact:

- **Email**: licensing@nervosys.ai
- **GitHub**: [github.com/nervosys](https://github.com/nervosys)

Commercial licenses are available with flexible terms tailored to your needs, including per-seat, per-deployment, and enterprise-wide options.

## What a License Does Not Cover

Neither license is a statement about cryptographic assurance. In particular:

- **No FIPS validation.** IronCrypto implements the FIPS 140-3 operational discipline but holds no CMVP certificate. A commercial license does not confer one. See [docs/FIPS.md](docs/FIPS.md).
- **No security audit.** The code has not been independently reviewed by cryptographers. See [SECURITY.md](SECURITY.md).
- **Warranty.** The AGPL version is provided without warranty, as stated in the licence. Warranty and indemnification terms, where offered, are set out in the commercial agreement rather than here.

## Contributor License Agreement (CLA)

All contributors must agree to the [Contributor License Agreement](CLA.md) before their contributions can be accepted. By submitting a pull request, you agree that your contributions may be distributed under both the AGPL v3 and commercial licenses. This enables the dual-licensing model to work for all users.

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.
