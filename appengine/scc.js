const securitycenterModule = require('./securitycenter')
const config = require('./settings.json')
const colos = require('./colos.json')

const { db } = require('./utilities')

class SCC {
  constructor (_assets = [], orgPath, sccClient, keyFile) {
    this.orgPath = `organizations/${config.GCLOUD_ORG}`
    this._assets = [this.orgPath].concat(_assets)
    this.sccClient = new securitycenterModule.SecurityCenterClient({
      keyFilename: keyFile || config['GOOGLE_APPLICATION_CREDENTIALS'],
      projectId: config['GCLOUD_PROJECT_ID']
    })
  }

  getFindings () {
    return this.sccClient
      .searchFindings({
        orgName: this.orgPath
      })
      .then(res => {
        console.log(JSON.stringify(res))
      })
  }

  get assets () {
    return [].concat(...this._assets)
  }

  set assets (assetArr) {
    Array.prototype.push.apply(this._assets, [assetArr])
  }

  async getAssets (query = 'INSTANCE', cfComparison = false) {
    let networkInstances = `content=`
    try {
      const results = await this.sccClient.searchAssets({
        orgName: this.orgPath,
        query: `asset_type = "${query}"`
      })
      await results[0].forEach(asset => {
        let network = JSON.parse(asset.properties.fields.networkInterfaces.stringValue)
        if (`${network[0].accessConfigs[0].natIP}` !== 'undefined') {
          networkInstances += `${network[0].accessConfigs[0].natIP},`
          this.assets = asset.id
        }
        // db.save(network[0].accessConfigs[0].natIP, asset.id)
      })
    } catch (e) {
      console.log('Error connecting to SCC API, reinitializing connection. ', e.metadata)
    }
    if (cfComparison) return networkInstances.slice(0, -1)
    return this.assets
  }
}

class Finding extends SCC {
  constructor (log, action, category, affectedAssets = []) {
    super(affectedAssets)
    this.action = action.toUpperCase()
    this.log = log
    this.category = category
    this.classification = this.log.WAFRuleMessage === '' ? 'IP' : this.log.WAFRuleMessage
    // A necessarily messy conversion for GCP's nanosecond proto
    this.secs = (Math.floor((Number(this.log.EdgeStartTimestamp.toString().substring(0, 13)))) / 1000)
    this.loc = this.log.ClientCountry.toUpperCase()
    this.protocol = `${this.log.ClientRequestProtocol} • ${this.log.ClientSSLProtocol} • ${this.log.ClientSSLCipher}`

    // Map EdgeColoID to the city where the colo resides
    const inChina = colos.slice(172).findIndex(colo => colo.colo_id === this.log.EdgeColoID)
    if (log.EdgeColoID <= 172) {
      this.colo = colos[this.log.EdgeColoID].colo_alias
    } else if (inChina > -1) {
      this.colo = colos[inChina].colo_alias
    } else {
      this.colo = this.loc
    }
  }

  submitFinding () {
    // console.log(this.newFinding())

    return this.sccClient
      .createFinding({
        orgName: this.orgPath,
        sourceFinding: this.newFinding()
      })
      .then(res => {
        console.log(`RayID ${res[0].id} logged to Security Command Center`)
      }).catch(e => {
        console.log('Error ', e)
      })
  }

  newFinding () {
    return {
      id: this.log.RayID,
      category: this.category,
      url: `https://dash.cloudflare.com/`,
      assetIds: this.assets,
      sourceId: 'CLOUDFLARE',
      eventTime: { seconds: this.secs, nanos: 0 },
      properties: {
        fields: {
          action: {
            stringValue: this.action,
            kind: 'stringValue'
          },
          type: {
            stringValue: this.classification,
            kind: 'stringValue'
          },
          status_code: {
            stringValue: this.log.EdgeResponseStatus,
            kind: 'stringValue'
          },
          country: {
            stringValue: this.loc,
            kind: 'stringValue'
          },
          client_ip: {
            stringValue: this.log.ClientIP,
            kind: 'stringValue'
          },
          host: {
            stringValue: this.log.ClientRequestHost,
            kind: 'stringValue'
          },
          payload: {
            stringValue: this.log.ClientRequestURI,
            kind: 'stringValue'
          },
          user_agent: {
            stringValue: this.log.ClientRequestUserAgent,
            kind: 'stringValue'
          },
          cloudflare_location: {
            stringValue: this.colo,
            kind: 'stringValue'
          },
          method: {
            stringValue: this.log.ClientRequestMethod,
            kind: 'stringValue'
          },
          protocol: {
            stringValue: this.protocol,
            kind: 'stringValue'
          }
        }
      }
    }
  }
}

module.exports.SCC = SCC
module.exports.Finding = Finding
