const gulp = require('gulp')
const run = require('gulp-run')
const inquirer = require('inquirer')
const opn = require('opn')
const { auth } = require('google-auth-library')
const Rx = require('rxjs')
const fuzzy = require('fuzzy')
const chalk = require('chalk')
const fs = require('fs-extra')
const MD5 = require('unique-string')
const hash = require('hash.js')
const ncp = require('copy-paste')
const minify = require('gulp-minify')
const concat = require('concat')
const argv = require('yargs').argv
const exec = require('child_process').exec

const { SCC } = require('./appengine/scc')
let config = fs.readJsonSync('./setup.json')
let basename = 'cloudflare-scc-0.1'
let child

child = exec('basename `git rev-parse --show-toplevel`',
  function (error, stdout, stderr) {
    basename = stdout
    process.env.BASENAME = stdout
    if (error !== null) {
      console.log('exec error: ' + error)
    }
    return basename
  })

const client = auth.getClient({
  scopes: 'https://www.googleapis.com/auth/cloud-platform'
})

/* Set configuration data to be added to Worker template */
const configure = (projectId) => {
  let prompts = new Rx.Subject()

  let terminal = {
    msg: `Starting CLI ...\n`,

    set current (text = '...') {
      this.msg = `${text}\n`
    },

    get current () {
      if (this.msg === undefined) return `\n...\n`
      return this.msg
    }
  }

  function output () {
    console.log(chalk.keyword('orange')(terminal.current))
  }

  inquirer.prompt(prompts).ui.process.subscribe(output)

  terminal.current = `...`

  config.GOOGLE['GCLOUD_PROJECT_ID'] = `${projectId}`

  prompts.next({
    type: 'list',
    name: 'billing',
    message: 'Is billing enabled for this project?',
    choices: ['Yes', 'No'],
    default: 'Yes',
    filter (input) {
      console.log(input)
      return new Promise((resolve, reject) => {
        terminal.current = `...`
        if (input === 'No') {
          terminal.current = `Please enable billing: https://console.developers.google.com/project/${projectId}/settings`
          setTimeout((done) => {
            opn(`https://console.developers.google.com/project/${projectId}/settings`)
            resolve()
            done = true
          }, 1000)
        } else {
          terminal.current = `Yes`
          resolve()
        }
      })
    }
  })

  prompts.next({
    type: 'list',
    name: 'sccKey',
    prefix: '',
    message: `\n* Download onto your local machine your SCC service account key as a JSON file here: https://console.cloud.google.com/iam-admin/serviceaccounts?project=${projectId}. \n* Rename it "scc_key.json" \n• Then, click on the Cloud Shell dot menu and select "Upload File ⋮"`,
    choices: ['Done'],
    filter (input) {
      return new Promise((resolve, reject) => {
        terminal.current = `Registered file in directory`
        setTimeout(() => {
          resolve()
        }, 200)
      })
    }
  })

  terminal.current = `Set Security Command Center proxy.`

  prompts.next({
    type: 'input',
    name: 'inputDomainPrompt',
    message: 'Choose a top-level domain to use for communication between SCC and Cloudflare. Note that all domains in your Cloudflare org will be available for polling threat data, regardless of the domain you choose.',
    default: 'example.com',
    validate (input) {
      terminal.current = `${input} will be your Security Command Center proxy host.`
      return true
    },
    filter (input) {
      return new Promise((resolve, reject) => {
        config.WORKERS['UNIQUE_LOGS_ENDPOINT'] = `${MD5()}.${input}`
        config.WORKERS['STRING_TO_SIGN'] = config.WORKERS['UNIQUE_LOGS_ENDPOINT']
        config.GOOGLE['UNIQUE_LOGS_ENDPOINT'] = config.WORKERS['UNIQUE_LOGS_ENDPOINT']
        config.GOOGLE['STRING_TO_SIGN'] = config.WORKERS['UNIQUE_LOGS_ENDPOINT']
        config.WORKERS['HMAC_SECRET_KEY'] = hash.sha256().update(`${Math.floor((Math.random() * Date.now()))}${Math.random().toString(36).replace(/[^a-z]+/g, '').substr(0, 16)}`).digest('hex')
        config.GOOGLE['HMAC_SECRET_KEY'] = config.WORKERS['HMAC_SECRET_KEY']
        resolve(input)
      })
    }
  })

  prompts.next({
    type: 'input',
    name: 'chooseTLDs',
    prefix: '>',
    message: `List all of the top-level domains you'd like to monitor on Security Command Center. Separate with commas ( example.com, website.com ):`,

    validate (input) {
      terminal.current = `Added sites to config`
      return true
    },
    filter (input) {
      return new Promise(async (resolve, reject) => {
        try {
          let zones = input.split(/\s*/).join('').split(',')
          config.GOOGLE['ZONE_NAMES'] = zones
          // db.writeFileToBucket('settings.json', config.GOOGLE, MD5('google-cloudflare-scc'))
        } catch (e) {
          console.log(e)
        }
        resolve(input)
      })
    }
  })

  prompts.next({
    type: 'input',
    name: 'googleOrgId',
    prefix: '>',
    message: `Enter your 12 digit Google Organization ID:`,
    validate (input) {
      terminal.current = `Writing config file ... `
      return true
    },
    filter (input) {
      console.log()
      return new Promise(async (resolve, reject) => {
        const settings = {
          workers: './workers/settings.json',
          google: './appengine/settings.json'
        }

        config.GOOGLE['GCLOUD_ORG'] = Number.parseInt(input, 10)

        try {
          await fs.outputJson(settings.google, config.GOOGLE, { spaces: 2, replacer: null })
          await fs.outputJson(settings.workers, config.WORKERS, { spaces: 2, replacer: null })
          let reader = await fs.readJson(settings.workers)
          console.log(reader)
        } catch (e) {
          console.log(e)
        }

        resolve(input)
      })
    }
  })

  prompts.next({
    type: 'list',
    name: 'openWorkersPrompt',
    message: `Next, you'll need to paste a code snippet into Cloudflare Workers.\nDownload Worker to local machine ▼`,
    choices: ['Yes', 'No'],
    validate (input) {
      terminal.current = '\nOpen Cloudflare dashboard: \nhttps://dash.cloudflare.com/?zone=workers'
      return true
    },
    filter (input) {
      return new Promise((resolve, reject) => {
        terminal.current = '\nOpen Cloudflare dashboard: \nhttps://dash.cloudflare.com/?zone=workers'
        resolve(input)
      })
    }
  })

  prompts.complete()
}

const assets = {
  async retrieve () {
    const getAssets = await new SCC().getAssets()
    start(getAssets)

    async function start (assets) {
      let prompts = new Rx.Subject()
      inquirer.prompt(prompts)

      inquirer.registerPrompt('autocomplete', require('inquirer-autocomplete-prompt'))

      let listMap = new Map()

      function searchAssets (answers, input) {
        input = input || ''
        return new Promise(function (resolve) {
          setTimeout(function () {
            var fuzzyResult = fuzzy.filter(input, assets)
            resolve(
              fuzzyResult.map(function (el) {
                return el.string
              })
            )
          }, 100)
        })
      }
      // assets = [
      //   chalk.keyword('orange')('lb.uswest.camilia.me') + '|' + 'kubectl-cluster-uswest-b',
      //   chalk.keyword('orange')('lb.eu.camilia.me') + '|' + 'kubectl-cluster-euwest-ac',
      //   'avatar-bucket'
      // ]

      const assetSearch = await prompts.next({
        type: 'autocomplete',
        name: 'assetSearch',
        message: `Search your asset inventory`,
        source: searchAssets
      })
      console.log(assetSearch)
      // await JSON.parse(JSON.stringify(assetSearch.answers, null, 2), (k, v) => {
      //   console.log(k, v)
      // })

      // ).then(function (answers) {
      //     JSON.parse(JSON.stringify(answers, null, 2), (k, v) => {
      //       if (k === 'cfAsset') console.log(JSON.stringify(listMap.get(v), null, 2))
      //     })
      //   })
    }
  }
}

gulp.task('compress', async function (cb) {
  return [gulp.src('workers/worker.js')
    .pipe(minify({
      ext: {
        src: '',
        min: '.min.js'
      },
      ignoreFiles: ['*.min.js', 'base.js'],
      noSource: true
    }))
    .pipe(gulp.dest('workers/')), cb]
})

gulp.task('write:settings', async function settings (cb) {
  try {
    concat(['./workers/settings.json', './workers/base.js', './workers/worker.min.js']).then(async result => {
      ncp.copy(`const settings = ${result}`)
      fs.writeFileSync('./workers/worker.compiled.js', `const settings = ${result}`)
    })
  } catch (e) {
    console.log(e)
  }
})

gulp.task('compile', gulp.series('compress', 'write:settings'))

gulp.task('configure', async function (cb) {
  const projectId = await auth.getDefaultProjectId()
  configure(projectId)
  // return sequence(['configure'], ['movekeys'], callback)
  cb()
})

gulp.task('enableapis', function (cb) {
  var cmd = new run.Command('npm run enableapis')
  console.log('Waiting for APIs to enable')
  cmd.exec()
  cb()
})

gulp.task('downloadFile', function (cb) {
  console.log(`cloudshell download ${basename}/workers/worker.compiled.js`)
  var cmd = new run.Command(`cloudshell download ${basename}/workers/worker.compiled.js`)
  console.log('Downloading ')
  cmd.exec()
  cb()
})

gulp.task('moveFile', function (cb) {
  console.log(basename)
  var cmd = new run.Command(`cd ~ && mv scc_key.json ~/${basename}`)
  cmd.exec()
  cb()
})

gulp.task('deploy', function (cb) {
  var cmd = new run.Command('cd appengine')
  console.log('Once the Worker is live on Cloudflare, you can initialize the SCC integration by running:')
  console.log(chalk.keyword('blue')('cd appengine && gcloud app deploy'))
  cmd.exec()
  cb()
})

gulp.task('cli', function (cb) {
})

gulp.task('cf:scc:assets', function (cb) {
  assets.retrieve()
  cb()
})
