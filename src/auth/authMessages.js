import { TokenSigner, createUnsecuredToken, SECP256K1Client } from 'jsontokens'

import {
  makeDIDFromAddress,
  makeUUID4,
  nextMonth,
  nextHour,
  publicKeyToAddress,
} from '../index'

require('isomorphic-fetch')

export function makeAuthRequest(privateKey, domainName, manifestURI = null,
  redirectURI = null, scopes = [], expiresAt = nextHour().getTime()) {
  if (domainName === null) {
    throw new Error('Invalid app domain name')
  }
  if (manifestURI === null) {
    manifestURI = `${domainName}/manifest.json`
  }
  if (redirectURI === null) {
    redirectURI = domainName
  }

  /* Create the payload */
  const payload = {
    jti: makeUUID4(),
    iat: Math.floor(new Date().getTime() / 1000), // JWT times are in seconds
    exp: Math.floor(expiresAt / 1000), // JWT times are in seconds
    iss: null,
    public_keys: [],
    domain_name: domainName,
    manifest_uri: manifestURI,
    redirect_uri: redirectURI,
    scopes: scopes,
  }

  if (privateKey === null) {
    /* Create an unsecured token and return it */
    const token = createUnsecuredToken(payload)
    return token
  } else {
    /* Convert the private key to a public key to an issuer */
    const publicKey = SECP256K1Client.derivePublicKey(privateKey)
    const address = publicKeyToAddress(publicKey)
    const newPayload = Object.assign(payload, {
      public_keys: [publicKey],
      iss: makeDIDFromAddress(address),
    })
    /* Sign and return the token */
    const tokenSigner = new TokenSigner('ES256k', privateKey)
    const token = tokenSigner.sign(newPayload)
    return token
  }
}

export function makeAuthResponse(privateKey, profile = {}, username = null,
  coreToken = null, expiresAt = nextMonth().getTime()) {
  /* Convert the private key to a public key to an issuer */
  const publicKey = SECP256K1Client.derivePublicKey(privateKey)
  const address = publicKeyToAddress(publicKey)

  /* Create the payload */
  const payload = {
    jti: makeUUID4(),
    iat: Math.floor(new Date().getTime() / 1000), // JWT times are in seconds
    exp: Math.floor(expiresAt / 1000), // JWT times are in seconds
    iss: makeDIDFromAddress(address),
    public_keys: [publicKey],
    profile: profile,
    username: username,
    core_token: coreToken,
  }

  /* Sign and return the token */
  const tokenSigner = new TokenSigner('ES256k', privateKey)
  return tokenSigner.sign(payload)
}
