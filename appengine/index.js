
const cron = require('node-cron')
const express = require('express')
const moment = require('moment')
const ndjson = require('ndjson')
const request = require('got')
const app = express()
const port = process.env.PORT || 8443
const once = require('once')
/*  https://github.com/openpgpjs/openpgpjs */
const openpgp = require('openpgp')

const config = require('./settings.json')
const { DB } = require('./utilities')
const { Finding } = require('./scc')
const db = new DB()
// var parse = require('parse-header-stream')

async function poll () {
  try {
    config.ZONE_NAMES.map(async zone => {
      const response = await request.stream(`https://${config.UNIQUE_LOGS_ENDPOINT}/${zone}?token=${db.token()}&fields=${config.FIELDS}`, {
        retry: {
          retries: 0,
          maxRetryAfter: 250
        },
        headers: {
          'User-Agent': 'Cloudflare SCC Agent'
        }
      })
      once(readLogs(response))
    })
  } catch (e) {
    return (e.response)
  }

  async function readLogs (response) {
    console.log(`Polled ELS on: ${moment()}`)
    response.pipe(ndjson.parse()).on('data', (log) => {
      // Threat-related codes from Cloudflare logs
      const wafBlock = (log.WAFRuleMessage !== '')
      const rateLimit = (log.EdgeRateLimitID > 0)
      const ipCode = ['ctry', 'ip', 'jschlNew', 'captchaNew', 'zl'].indexOf(log.EdgePathingStatus)

      let assets = [log.OriginIP]

      let finding

      switch (true) {
        case (!log.WAFAction && !log.EdgePathingStatus && !log.EdgeRateLimitID):
          throw 'No new threats'

        case wafBlock:
          finding = new Finding(log, log.WAFAction, log.WAFRuleMessage, assets)
          break

        case rateLimit:
          finding = new Finding(log, log.EdgeRateLimitAction, 'Rate Limit Exceeded', assets)
          break

        case ipCode > -1:
          const threatCodeDefinitions = ['Country Block', 'IP Block', 'IP Firewall JS Challenge', 'IP Captcha Challenge', 'IP Zone Lockdown']
          finding = new Finding(log, log.EdgePathingOp, threatCodeDefinitions[ipCode], assets)
          break

        default:
          return
      }
      return finding.submitFinding()
    })
  }
}

/*
 * Check database for existing PGP public/private key pair. If no pair is found, generate a new one
 * Once PGP public key is available, return it to the client
*/
app.get('/', async (req, res) => {
  const response = message => res.status(200).json({ 'publicKey': message })
  const db = new DB()
  return db.exists('PGP_Public').then(entry => {
    // If the "PGP_Public" query is found in the db
    // return the public key
    if (entry) return response(entry.public)
  })
})

app.get('/new-key', async (req, res) => {
  let opts = {
    userIds: [{ email: 'customer@cloudflare.com' }],
    curve: 'ed25519'
  }

  openpgp.generateKey(opts).then(keyPair => {
    return db.save('PGP_Public', {
      public: keyPair.publicKeyArmored,
      private: keyPair.privateKeyArmored,
      revocationSignature: keyPair.revocationSignature
    })
    // console.log(keyPair)
  })
})

app.post('/listen', (req, res) => {
  console.log(req.body)
})

const logger = cron.schedule('* * * * *', () => {
  return poll()
}, false)

logger.start()

app.listen(port)
console.log('\nϟϟϟ Serving on port ' + port + ' ϟϟϟ\n')
