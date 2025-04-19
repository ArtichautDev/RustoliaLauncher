
const AuthClient = require('azuriom-auth').AuthClient
const email = "admin@onpowered.net"
const password = "rebsom-8qosmy-tajcEb"

login(email, password)
  .then((result) => {
    console.log('Login successful:', result)
  })
  .catch((error) => {
    console.error('Login failed:', error)
  })

async function login(email, password) {
  const client = new AuthClient('https://rustolia.eu')

  let result = await client.login(email, password)

  if (result.status === 'pending' && result.requires2fa) {
    const twoFactorCode = '<two factor code>' // IMPORTANT: Replace with the 2FA user temporary code

    result = await client.login(email, password, twoFactorCode)
  }

  if (result.status !== 'success') {
    throw 'Unexpected result: ' + JSON.stringify(result)
  }

  return result
}
login