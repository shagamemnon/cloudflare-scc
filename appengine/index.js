
const cron = require('node-cron')
const express = require('express')
const moment = require('moment')
const ndjson = require('ndjson')
const request = require('got')
const app = express()
const port = process.env.PORT || 8443
const once = require('once')
/*  https://github.com/openpgpjs/openpgpjs */
const config = require('./settings.json')
const { DB } = require('./utilities')
const { Finding } = require('./scc')
// var parse = require('parse-header-stream')

async function poll () {
  try {
    config.ZONE_NAMES.map(async zone => {
      console.log(`https://${config.UNIQUE_LOGS_ENDPOINT}/${zone}?token=${DB.token()}&fields=${config.FIELDS}`)
      const response = await request.stream(`https://${config.UNIQUE_LOGS_ENDPOINT}/${zone}?token=${DB.token()}&fields=${config.FIELDS}`, {
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

const logger = cron.schedule('* * * * *', () => {
  return poll()
}, false)

logger.start()

app.listen(port)
console.log('\nϟϟϟ Serving on port ' + port + ' ϟϟϟ\n')
