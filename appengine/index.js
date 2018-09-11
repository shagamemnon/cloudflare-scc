const express = require('express')
const moment = require('moment')
const ndjson = require('ndjson')
const request = require('got')
const once = require('once')
const config = require('./settings.json')

const cron = require('node-cron')
const crypto = require('crypto')

const port = process.env.PORT || 3000
const app = express()

async function getLogs () {
  const authToken = crypto.createHmac('sha256', config.HMAC_SECRET_KEY).update(config.UNIQUE_LOGS_ENDPOINT).digest('base64')
  try {
    config.ZONE_NAMES.map(async zone => {
      console.log(`https://${config.UNIQUE_LOGS_ENDPOINT}/${zone}?token=${authToken}&fields=${config.FIELDS}`)
      const response = await request.stream(`https://${config.UNIQUE_LOGS_ENDPOINT}/${zone}?token=${authToken}&fields=${config.FIELDS}`, {
        retry: {
          retries: 1,
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

cron.schedule('*/10 * * * * *', () => {
  getLogs()
})

app.listen(port)
console.log('\nϟϟϟ Serving on port ' + port + ' ϟϟϟ\n')
