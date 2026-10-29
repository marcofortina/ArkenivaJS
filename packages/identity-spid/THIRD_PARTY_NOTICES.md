# Third-party notices

The adapter uses the unmodified `@xmldom/xmldom` 0.8.15 and `xml-crypto` 6.4.0
packages under their MIT licenses. Their original copyright and license notices
remain in the distributed dependencies. ArkenivaJS delegates XML parsing and
cryptographic signature operations to these packages and copies no implementation
from them.

The SAML signature primitive consumes only references authenticated by
`SignedXml.getSignedReferences()` after successful signature verification. It
ignores embedded key selection and applies its own explicit root, algorithm and
bounded metadata policy. A signature result alone does not establish current
federation membership, revocation status or official SPID interoperability.
