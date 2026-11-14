// Package daneauth provides server and client configuration for TLS client
// authentication with DANE (draft-ietf-dance-client-auth), built on
// github.com/shuque/daneclient/tls and github.com/shuque/dane/v2.
//
// # Server behaviour (draft section 8.2)
//
// TLS 1.3 only: NewServer sets MinVersion to TLS 1.3, and disables session
// tickets because a resumed connection carries no ClientName. The draft's
// steps map to the code as follows ("VerifyConnection step N" is the step
// numbering in Server.verify and its Logf lines):
//
//   - 1, request a certificate with an empty dane_clientid: NewServer
//     (DANEClientAuth, ClientAuth per Policy); the fork builds the
//     CertificateRequest.
//   - 2, receive the Certificate and its dane_clientid: the fork, which
//     exposes the name as ConnectionState.DANEClientName.
//   - 3, extract the name: a zero-length ClientName is rejected by the fork
//     with handshake_failure; an absent one is VerifyConnection step 1
//     ("no dane_clientid").
//   - 4, authorization rules, then the DNSSEC-validated TLSA lookup at the
//     ClientName: VerifyConnection step 2 (Allowlist, "name not allowed",
//     no DNS query) and step 3 (bounded by LookupTimeout, cached per TTL,
//     AD bit required by dane.Resolver; "tlsa lookup: ...").
//   - 5 and 6, match the records against the chain, any one record
//     sufficing, with digest agility: VerifyConnection step 4, dane.Verify
//     with RoleClient ("no matching tlsa").
//   - The ClientName must match a SAN dNSName where names are checked:
//     dane.Verify ("name mismatch").
//   - The name is made available to the application: Result and
//     AuthResult.ClientName, after VerifyConnection step 5
//     ("authenticated").
//
// Under Required every failure aborts with handshake_failure; under
// Optional the handshake completes and the client is unauthenticated.
// Result returns nil until the handshake has completed, because
// VerifyConnection runs before the client's CertificateVerify is checked.
package daneauth
