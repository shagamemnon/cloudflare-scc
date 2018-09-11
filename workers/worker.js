
const WorkersSCC = {
  App: class App {
    constructor (req, config) {
      this.req = this.request = new Request(req)
      this.url = new URL(req.url)
      this.headers = new Headers(req.headers)
      this.config = config = {
        'headers': {
          'X-Auth-Key': SETTINGS.API_KEY,
          'X-Auth-Email': SETTINGS.EMAIL,
          'Content-Type': 'application/json'
        },
        'ORG_NAME': SETTINGS.CLOUDFLARE_ORG_NAME,
        'SETUP_ENDPOINT': SETTINGS.SETUP_ENDPOINT,
        'WORKERS_MULTISCRIPT': SETTINGS.WORKERS_MULTISCRIPT,
        'SETUP': SETTINGS.SETUP,
        'HMAC_SECRET_KEY': SETTINGS.HMAC_SECRET_KEY,
        'STRING_TO_SIGN': SETTINGS.STRING_TO_SIGN,
        'UNIQUE_LOGS_ENDPOINT': SETTINGS.UNIQUE_LOGS_ENDPOINT
      }
      switch (true) {
        case (this.url.hostname.includes('cloudflare')):
          console.log('line 33')
          return this.establishZoneSettings()

        case SETTINGS.UNIQUE_LOGS_ENDPOINT === this.url.hostname:
          console.log('line 60')
          return this.pollELS()

        case this.url.pathname.includes('/dns-records'):
          return this.getOrigins()

        default:
          return this.rejectRequest()
      }
    }

    async rejectRequest (e = 'Operation Forbidden') {
      return new Response(e, {
        status: 403,
        statusText: 'Forbidden'
      })
    }

    get zoneID () {
      return (async () => {
        try {
          const getZoneId = await fetch('https://api.cloudflare.com/client/v4/zones', { headers: this.config.headers })
          const res = await getZoneId.json()
          let target = this.url.pathname.split('/')[1]
          if (this.url.pathname.startsWith('/scc-setup')) target = this.config.UNIQUE_LOGS_ENDPOINT.split('.').splice(1, 3).join('.')

          for (let i = 0; i < res.result.length; i++) {
            if (res.result[i].name === target) {
              return res.result[i].id
            }
          }
        } catch (e) {
          return this.rejectRequest(e)
        }
      })()
    }

    get orgID () {
      return (async () => {
        try {
          const getOrgId = await fetch('https://api.cloudflare.com/client/v4/zones', { headers: this.config.headers })
          const res = await getZoneId.json()

          for (let i = 0; i < res.result.length; i++) {
            if (res.result[i].name === this.config.ORG_NAME) {
              return res.result[i].id
            }
          }
        } catch (e) {
          return this.rejectRequest(e)
        }
      })()
    }

    async pollELS () {
      if (!this.HMAC('validate')) return this.rejectRequest('Token validation failed')

      this.url.searchParams.delete('token')
      const isoTime = (ago, output = '') => {
        let d = new Date()
        d.setTime(d.getTime() + ago * 60000)
        let isoNow = JSON.parse(JSON.stringify(d))
        output = (`${isoNow.substring(0, 16)}:00Z`)
        return output
      }
      let fields = this.url.searchParams.get('fields')
      const poll = await fetch(`https://api.cloudflare.com/client/v4/zones/${await this.zoneID}/logs/received?start=${isoTime(-10)}&end=${isoTime(-6)}&fields=${fields}`, { headers: this.config.headers })
      // const postToGoogle = fetch('http://localhost:8443', { headers: { 'Content-Type': 'text/plain' }, method: 'POST', body: await poll.text() })
      return poll
    }

    async establishZoneSettings () {
      if (!this.config.SETUP) {
        return new Response('Not Found', { status: 404 })
      }

      const user = (function (previewModeHTML, apiPayload) {
        let html = `<html>`
        let data = {
          'pattern': `https://${this.config.UNIQUE_LOGS_ENDPOINT}/*`
        }
        if (this.config.WORKERS_MULTISCRIPT) {
          data['script'] = 'scc_cloudflare'
          html += `<h4 style='font-family: "Open Sans"; font-weight: 300'>It looks like you're using Workers Multiscript. Name this script <code style='padding-left:3px;padding-right:3px;position:relative;top:-1px'>scc_cloudflare</code> before continuing.</h4>`
        } else {
          data['enabled'] = true
        }
        html += `<form action="/scc-setup" method="post"><input type="submit" value="Submit"></form>`
        html += `</html>`
        console.log(data)
        return {
          previewModeHTML: html,
          apiPayload: JSON.stringify(data)
        }
      })()

      if (this.request.method === 'GET') {
        return new Response(user.previewModeHTML, { headers: { 'Content-Type': 'text/html' } })
      }

      /**
     * Make three fetch requests to the Cloudflare API:
     * – Add DNS record that corresponds to this.config.UNIQUE_LOGS_ENDPOINT
     * - Apply Zone Lockdown settings to * routes under this endpoint allowing only GCP IPs
     * – Add Workers route that corresponds to this.config.UNIQUE_LOGS_ENDPOINT
    */
      const [addRecords, lockdownZone, setWorkerRoutes] = [
        await fetch(`https://api.cloudflare.com/client/v4/zones/${await this.zoneID}/dns_records`, {
          headers: this.config.headers,
          method: 'POST',
          body: JSON.stringify({
            'proxied': true,
            'content': 'cloud.google.com',
            'ttl': 1,
            'type': 'CNAME',
            'name': `${this.config.UNIQUE_LOGS_ENDPOINT}`
          })
        }),

        await fetch(`https://api.cloudflare.com/client/v4/zones/${await this.zoneID}/firewall/lockdowns`, {
          headers: this.config.headers,
          method: 'POST',
          body: JSON.stringify({
            'configurations': [
              {
                'target': 'ip_range',
                'value': '8.34.208.0/20'
              },
              {
                'target': 'ip_range',
                'value': '8.35.192.0/21'
              },
              {
                'target': 'ip_range',
                'value': '8.35.200.0/23'
              },
              {
                'target': 'ip_range',
                'value': '108.59.80.0/20'
              },
              {
                'target': 'ip_range',
                'value': '108.170.192.0/20'
              },
              {
                'target': 'ip_range',
                'value': '108.170.208.0/21'
              },
              {
                'target': 'ip_range',
                'value': '108.170.216.0/22'
              },
              {
                'target': 'ip_range',
                'value': '108.170.220.0/23'
              },
              {
                'target': 'ip_range',
                'value': '108.170.222.0/24'
              },
              {
                'target': 'ip_range',
                'value': '35.224.0.0/13'
              },
              {
                'target': 'ip_range',
                'value': '162.216.148.0/22'
              },
              {
                'target': 'ip_range',
                'value': '162.222.176.0/21'
              },
              {
                'target': 'ip_range',
                'value': '173.255.112.0/20'
              },
              {
                'target': 'ip_range',
                'value': '192.158.28.0/22'
              },
              {
                'target': 'ip_range',
                'value': '199.192.112.0/22'
              },
              {
                'target': 'ip_range',
                'value': '199.223.232.0/22'
              },
              {
                'target': 'ip_range',
                'value': '199.223.236.0/23'
              },
              {
                'target': 'ip_range',
                'value': '23.236.48.0/20'
              },
              {
                'target': 'ip_range',
                'value': '23.251.128.0/19'
              },
              {
                'target': 'ip_range',
                'value': '35.204.0.0/14'
              },
              {
                'target': 'ip_range',
                'value': '35.208.0.0/14'
              },
              {
                'target': 'ip_range',
                'value': '107.167.160.0/19'
              },
              {
                'target': 'ip_range',
                'value': '107.178.192.0/18'
              },
              {
                'target': 'ip_range',
                'value': '146.148.2.0/23'
              },
              {
                'target': 'ip_range',
                'value': '146.148.4.0/22'
              },
              {
                'target': 'ip_range',
                'value': '146.148.8.0/21'
              },
              {
                'target': 'ip_range',
                'value': '146.148.16.0/20'
              },
              {
                'target': 'ip_range',
                'value': '146.148.32.0/19'
              },
              {
                'target': 'ip_range',
                'value': '146.148.64.0/18'
              },
              {
                'target': 'ip_range',
                'value': '35.203.0.0/17'
              },
              {
                'target': 'ip_range',
                'value': '35.203.128.0/18'
              },
              {
                'target': 'ip_range',
                'value': '35.203.192.0/19'
              },
              {
                'target': 'ip_range',
                'value': '35.203.240.0/20'
              },
              {
                'target': 'ip_range',
                'value': '130.211.8.0/21'
              },
              {
                'target': 'ip_range',
                'value': '130.211.16.0/20'
              },
              {
                'target': 'ip_range',
                'value': '130.211.32.0/19'
              },
              {
                'target': 'ip_range',
                'value': '130.211.64.0/18'
              },
              {
                'target': 'ip_range',
                'value': '130.211.128.0/17'
              },
              {
                'target': 'ip_range',
                'value': '104.154.0.0/15'
              },
              {
                'target': 'ip_range',
                'value': '104.196.0.0/14'
              },
              {
                'target': 'ip_range',
                'value': '208.68.108.0/23'
              },
              {
                'target': 'ip_range',
                'value': '35.184.0.0/14'
              },
              {
                'target': 'ip_range',
                'value': '35.188.0.0/15'
              },
              {
                'target': 'ip_range',
                'value': '35.202.0.0/16'
              },
              {
                'target': 'ip_range',
                'value': '35.190.0.0/17'
              },
              {
                'target': 'ip_range',
                'value': '35.190.128.0/18'
              },
              {
                'target': 'ip_range',
                'value': '35.190.192.0/19'
              },
              {
                'target': 'ip_range',
                'value': '35.235.224.0/20'
              },
              {
                'target': 'ip_range',
                'value': '35.192.0.0/14'
              },
              {
                'target': 'ip_range',
                'value': '35.196.0.0/15'
              },
              {
                'target': 'ip_range',
                'value': '35.198.0.0/16'
              },
              {
                'target': 'ip_range',
                'value': '35.199.0.0/17'
              },
              {
                'target': 'ip_range',
                'value': '35.199.128.0/18'
              },
              {
                'target': 'ip_range',
                'value': '35.200.0.0/15'
              },
              {
                'target': 'ip_range',
                'value': '2600:1900::/35'
              }
            ],
            'paused': false,
            'description': 'Restrict access to Google Cloud Engine',
            'urls': [
              `https://${this.config.UNIQUE_LOGS_ENDPOINT}/*`
            ]
          })
        }),
        await fetch(`https://api.cloudflare.com/client/v4/zones/${await this.zoneID}/workers/${this.config.WORKERS_MULTISCRIPT ? `routes` : `filters`}`, {
          headers: this.config.headers,
          method: 'POST',
          body: user.apiPayload
        })
      ]

      const [dns, lockdown, routes] = [
        await addRecords.json(),
        await lockdownZone.json(),
        await setWorkerRoutes.json()
      ]

      let combined = {}
      combined['dns'] = dns
      combined['lockdown'] = lockdown
      combined['routes'] = routes

      let resMsg = ''

      if (!combined['dns'].success && !combined['lockdown'].errors[0].code === 81053) {
        return new Response(`Error applying DNS settings: ${combined['dns'].errors[0].code}`)
      } else {
        resMsg += `Success! ${this.config.UNIQUE_LOGS_ENDPOINT}`
        combined['dns'].success ? resMsg += ` was added to your DNS panel ` : resMsg += ` is already in your DNS panel `
      }

      if (!combined['lockdown'].success && !combined['lockdown'].errors[0].code === 10009) {
        return new Response(`Error applying Zone Lockdown settings: ${combined['lockdown'].errors[0].message}`)
      } else {
        combined['lockdown'] ? resMsg += `and has been locked down to Google's IP space. ` : resMsg += `and is now locked down to Google Cloud's IP space. `
      }

      if (!combined['routes'].success && !combined['routes'].errors[0].code === 10020) {
        return new Response(`Error worker route: ${combined['routes'].errors[0].message}`)
      } else {
        resMsg += `All requests to this subdomain are running through the Workers integration with SCC.`
      }

      resMsg += `\n\nThis page is only visible in the Workers browser, but you can turn it off by modifying the settings --> SETUP option on top of this Worker script.`

      return new Response(resMsg, {
        status: 200,
        headers: {
          'Content-Type': 'application/json'
        }
      })
    }

    async getOrigins (_request, url) {
      this.request = _request
      const response = await fetch(`https://api.cloudflare.com/client/v4/zones/${await this.zoneID}/dns_records/${url.search}`, { headers: this.config.headers })
      return response
    }

    async HMAC (action = 'validate', validationToken) {
      const secretKey = this.config.HMAC_SECRET_KEY
      const strToSign = this.config.STRING_TO_SIGN

      const clientToken = (function (str = '') {
        // Decode Base64 URL string
        // str =
        str = (str + '=').slice(0, str.length + (str.length % 4))
        str.replace(/-/g, '+').replace(/_/g, '/')
        return encodeURIComponent(str)
      })(this.url.searchParams.get('token'))

      const str2ab = (str, uintArray) => {
        uintArray = new Uint8Array(str.split('').map(function (char) { return char.charCodeAt(0) }))
        return uintArray
      }

      const key = await crypto.subtle.importKey('raw', str2ab(secretKey), {
        name: 'HMAC',
        hash: {
          name: 'SHA-256'
        }
      }, false, ['sign', 'verify'])

      const sig = await crypto.subtle.sign({
        name: 'HMAC'
      }, key, str2ab(strToSign))

      validationToken = encodeURIComponent(btoa(String.fromCharCode.apply(null, new Uint8Array(sig))))

      switch (action) {
        case 'generate':
          return validationToken

        case 'validate':
          if (await validationToken === clientToken) return true
          return false

        default:
          return false
      }
    }
  },

  handleRequest (request) {
    return new this.App(request)
  }
}
