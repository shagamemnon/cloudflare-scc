const settings = {
  "headers": {
    "X-Auth-Key": "",
    "X-Auth-Email": "",
    "Content-Type": "application/json"
  },
  "ORG_NAME": "",
  "HMAC_SECRET_KEY": "eaab72df9173e8f3f95cc1be6676f6cb21b9f0a428ef6403e2fd930430a48cab",
  "STRING_TO_SIGN": "9a8a1e5af55c62e87b06fd9cc6646afb.franktaylor.io",
  "UNIQUE_LOGS_ENDPOINT": "9a8a1e5af55c62e87b06fd9cc6646afb.franktaylor.io",
  "SETUP_ENDPOINT": "https: //cloudflare.com/scc-setup",
  "WORKERS_MULTISCRIPT": false,
  "SETUP": true
}

/*
 *
 *
 * Enter https://cloudflare.com/scc-setup in the Browser Preview
 *
 *
 *
*/

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest (request) {
  let url = new URL(request.url)
  WorkersSCC.request = request
  return WorkersSCC.handleRequest(request)

  switch (true) {
    case (url.href === 'https://cloudflare.com/scc-setup'):
      return WorkersSCC.establishZoneSettings()

    case (url.hostname === settings['UNIQUE_LOGS_ENDPOINT'] && WorkersSCC.HMAC('validate')):
      return WorkersSCC.pollELS()

    case url.href.includes('/dns-records'):
      return WorkersSCC.getOrigins()

    case (WorkersSCC.acceptsRoute(request.headers)):
      return WorkersSCC.handleRequest()

    default:
      return WorkersSCC.rejectRequest()
  }
  return WorkersSCC.rejectRequest()
}

/*
 *
 *
 *
 *
*/

const WorkersSCC={_url:"",_request:"",_headers:"",set request(e){this._request=new Request(e),this._url=new URL(e.url),this._headers=new Headers(e.headers)},get url(){return this._url},get request(){return this._request},get headers(){return this._headers},rejectRequest:async(e="Operation Forbidden")=>new Response(e,{status:403,statusText:"Forbidden"}),acceptsRoute:async e=>e.get("Host")===settings.UNIQUE_LOGS_ENDPOINT||!(!settings.SETUP||!settings.SETUP_ENDPOINT.includes(e.get("Host"))),async handleRequest(e){this.request=e;try{return"https://cloudflare.com/scc-setup"===this.url.href?this.establishZoneSettings():this.url.hostname===settings.UNIQUE_LOGS_ENDPOINT&&this.HMAC("validate")?this.pollELS():this.rejectRequest("Endpoint not found")}catch(e){return console.log(e),this.rejectRequest("Endpoint not found")}},get zoneID(){return(async()=>{try{const e=await fetch("https://api.cloudflare.com/client/v4/zones",{headers:settings.headers}),t=await e.json();let a=this.url.pathname.split("/")[1];this.url.pathname.startsWith("/scc-setup")&&(a=settings.UNIQUE_LOGS_ENDPOINT.split(".").splice(1,3).join("."));for(let e=0;e<t.result.length;e++)if(t.result[e].name===a)return t.result[e].id}catch(e){return this.rejectRequest(e)}})()},get orgID(){return(async()=>{try{await fetch("https://api.cloudflare.com/client/v4/zones",{headers:settings.headers});const e=await getZoneId.json();for(let t=0;t<e.result.length;t++)if(e.result[t].name===settings.ORG_NAME)return e.result[t].id}catch(e){return this.rejectRequest(e)}})()},async pollELS(){this.url.searchParams.delete("token");const e=(e,t="")=>{let a=new Date;return a.setTime(a.getTime()+6e4*e),`${JSON.parse(JSON.stringify(a)).substring(0,16)}:00Z`};let t=this.url.searchParams.get("fields");return await fetch(`https://api.cloudflare.com/client/v4/zones/${await this.zoneID}/logs/received?start=${e(-10)}&end=${e(-6)}&fields=${t}`,{headers:settings.headers})},async establishZoneSettings(){if(!settings.SETUP)return new Response("Not Found",{status:404});const e=function(e,t){let a="<html>",r={pattern:`https://${settings.UNIQUE_LOGS_ENDPOINT}/*`};return settings.WORKERS_MULTISCRIPT?(r.script="scc_cloudflare",a+="<h4 style='font-family: \"Open Sans\"; font-weight: 300'>It looks like you're using Workers Multiscript. Name this script <code style='padding-left:3px;padding-right:3px;position:relative;top:-1px'>scc_cloudflare</code> before continuing.</h4>"):r.enabled=!0,a+='<form action="/scc-setup" method="post"><input type="submit" value="Submit"></form>',a+="</html>",console.log(r),{previewModeHTML:a,apiPayload:JSON.stringify(r)}}();if("GET"===this.request.method)return new Response(e.previewModeHTML,{headers:{"Content-Type":"text/html"}});const[t,a,r]=[await fetch(`https://api.cloudflare.com/client/v4/zones/${await this.zoneID}/dns_records`,{headers:settings.headers,method:"POST",body:JSON.stringify({proxied:!0,content:"cloud.google.com",ttl:1,type:"CNAME",name:`${settings.UNIQUE_LOGS_ENDPOINT}`})}),await fetch(`https://api.cloudflare.com/client/v4/zones/${await this.zoneID}/firewall/lockdowns`,{headers:settings.headers,method:"POST",body:JSON.stringify({configurations:[{target:"ip_range",value:"8.34.208.0/20"},{target:"ip_range",value:"8.35.192.0/21"},{target:"ip_range",value:"8.35.200.0/23"},{target:"ip_range",value:"108.59.80.0/20"},{target:"ip_range",value:"108.170.192.0/20"},{target:"ip_range",value:"108.170.208.0/21"},{target:"ip_range",value:"108.170.216.0/22"},{target:"ip_range",value:"108.170.220.0/23"},{target:"ip_range",value:"108.170.222.0/24"},{target:"ip_range",value:"35.224.0.0/13"},{target:"ip_range",value:"162.216.148.0/22"},{target:"ip_range",value:"162.222.176.0/21"},{target:"ip_range",value:"173.255.112.0/20"},{target:"ip_range",value:"192.158.28.0/22"},{target:"ip_range",value:"199.192.112.0/22"},{target:"ip_range",value:"199.223.232.0/22"},{target:"ip_range",value:"199.223.236.0/23"},{target:"ip_range",value:"23.236.48.0/20"},{target:"ip_range",value:"23.251.128.0/19"},{target:"ip_range",value:"35.204.0.0/14"},{target:"ip_range",value:"35.208.0.0/14"},{target:"ip_range",value:"107.167.160.0/19"},{target:"ip_range",value:"107.178.192.0/18"},{target:"ip_range",value:"146.148.2.0/23"},{target:"ip_range",value:"146.148.4.0/22"},{target:"ip_range",value:"146.148.8.0/21"},{target:"ip_range",value:"146.148.16.0/20"},{target:"ip_range",value:"146.148.32.0/19"},{target:"ip_range",value:"146.148.64.0/18"},{target:"ip_range",value:"35.203.0.0/17"},{target:"ip_range",value:"35.203.128.0/18"},{target:"ip_range",value:"35.203.192.0/19"},{target:"ip_range",value:"35.203.240.0/20"},{target:"ip_range",value:"130.211.8.0/21"},{target:"ip_range",value:"130.211.16.0/20"},{target:"ip_range",value:"130.211.32.0/19"},{target:"ip_range",value:"130.211.64.0/18"},{target:"ip_range",value:"130.211.128.0/17"},{target:"ip_range",value:"104.154.0.0/15"},{target:"ip_range",value:"104.196.0.0/14"},{target:"ip_range",value:"208.68.108.0/23"},{target:"ip_range",value:"35.184.0.0/14"},{target:"ip_range",value:"35.188.0.0/15"},{target:"ip_range",value:"35.202.0.0/16"},{target:"ip_range",value:"35.190.0.0/17"},{target:"ip_range",value:"35.190.128.0/18"},{target:"ip_range",value:"35.190.192.0/19"},{target:"ip_range",value:"35.235.224.0/20"},{target:"ip_range",value:"35.192.0.0/14"},{target:"ip_range",value:"35.196.0.0/15"},{target:"ip_range",value:"35.198.0.0/16"},{target:"ip_range",value:"35.199.0.0/17"},{target:"ip_range",value:"35.199.128.0/18"},{target:"ip_range",value:"35.200.0.0/15"},{target:"ip_range",value:"2600:1900::/35"}],paused:!1,description:"Restrict access to Google Cloud Engine",urls:[`https://${settings.UNIQUE_LOGS_ENDPOINT}/*`]})}),await fetch(`https://api.cloudflare.com/client/v4/zones/${await this.zoneID}/workers/${settings.WORKERS_MULTISCRIPT?"routes":"filters"}`,{headers:settings.headers,method:"POST",body:e.apiPayload})],[s,n,i]=[await t.json(),await a.json(),await r.json()];let o={};o.dns=s,o.lockdown=n,o.routes=i;let g="";return o.dns.success||81053!==!o.lockdown.errors[0].code?(g+=`Success! ${settings.UNIQUE_LOGS_ENDPOINT}`,o.dns.success?g+=" was added to your DNS panel ":g+=" is already in your DNS panel ",o.lockdown.success||10009!==!o.lockdown.errors[0].code?(o.lockdown?g+="and has been locked down to Google's IP space. ":g+="and is now locked down to Google Cloud's IP space. ",o.routes.success||10020!==!o.routes.errors[0].code?(g+="All requests to this subdomain are running through the Workers integration with SCC.",g+="\n\nThis page is only visible in the Workers browser, but you can turn it off by modifying the settings --\x3e SETUP option on top of this Worker script.",new Response(g,{status:200,headers:{"Content-Type":"application/json"}})):new Response(`Error worker route: ${o.routes.errors[0].message}`)):new Response(`Error applying Zone Lockdown settings: ${o.lockdown.errors[0].message}`)):new Response(`Error applying DNS settings: ${o.dns.errors[0].code}`)},async getOrigins(e,t){return this.request=e,await fetch(`https://api.cloudflare.com/client/v4/zones/${await this.zoneID}/dns_records/${t.search}`,{headers:settings.headers})},async HMAC(e="validate",t){const a=settings.HMAC_SECRET_KEY,r=settings.STRING_TO_SIGN,s=function(e=""){return(e=(e+"=").slice(0,e.length+e.length%4)).replace(/-/g,"+").replace(/_/g,"/"),encodeURIComponent(e)}(this.url.searchParams.get("token")),n=(e,t)=>new Uint8Array(e.split("").map(function(e){return e.charCodeAt(0)})),i=await crypto.subtle.importKey("raw",n(a),{name:"HMAC",hash:{name:"SHA-256"}},!1,["sign","verify"]),o=await crypto.subtle.sign({name:"HMAC"},i,n(r));switch(t=encodeURIComponent(btoa(String.fromCharCode.apply(null,new Uint8Array(o)))),e){case"generate":return t;case"validate":return await t===s;default:return!1}}};