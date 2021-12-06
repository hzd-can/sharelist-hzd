/**
 * 189Cloud Drive By Cookies
 */

const protocol = 'ctch'

const DEFAULT_ROOT_ID = '-11'

const UPLOAD_PART_SIZE = 10 * 1024 * 1024

const crypto = require('crypto')

const NodeRSA = require('node-rsa')

const urlFormat = require('url').format

const safeJSONParse = (data) =>
  JSON.parse(
    data.replace(/(?<=:\s*)(\d+)/g, ($0, $1) => {
      if (!Number.isSafeInteger(+$1)) {
        return `"${$1}"`
      } else {
        return $1
      }
    }),
  )

const sleep = (time) => new Promise((resolve) => setTimeout(resolve, time))

const hmac = (v, key) => {
  return crypto.createHmac('sha1', key).update(v).digest('hex')
}

const md5 = (v) => crypto.createHash('md5').update(v).digest('hex')

// const base64Hex = v => Buffer.from(v).toString('base64')

const aesEncrypt = (data, key, iv = "") => {
  let cipher = crypto.createCipheriv('aes-128-ecb', key, iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted
}

const rsaEncrypt = (data, publicKey, charset = 'base64') => {
  publicKey = '-----BEGIN PUBLIC KEY-----\n' + publicKey + '\n-----END PUBLIC KEY-----'

  let key = new NodeRSA(publicKey, { encryptionScheme: 'pkcs1' })
  return key.encrypt(data, charset)
}

const uuid = (v) => {
  return v.replace(/[xy]/g, (e) => {
    var t = 16 * Math.random() | 0
      , i = "x" === e ? t : 3 & t | 8;
    return i.toString(16)
  })
}

const qs = d => Object.keys(d).map(i => `${i}=${encodeURI(d[i])}`).join('&')

const parseHeaders = v => {
  let ret = {}
  for (let pair of decodeURIComponent(v).split('&').map(i => i.split('='))) {
    ret[pair[0].toLowerCase()] = pair.slice(1).join('=')
  }
  return ret
}
/**
 * auth manager class
 */
class Manager {
  static getInstance(app, helper) {
    if (!this.instance) {
      this.instance = new Manager(app, helper)
    }
    this.instance.init()
    return this.instance
  }

  constructor(app) {
    this.app = app
  }

  async init() {
    this.clientMap = {}
    let d = await this.app.getDrives()
    for (let i of d) {
      let data = this.app.decode(i.path)

      let { key } = data
      let needUpdate = false

      if (!key && data.account) {
        data.key = key = data.account
        needUpdate = true
      }

      if (key) {
        let isUsedKey = this.clientMap[key]
        if (isUsedKey) {
          data.key = key = `${key}.${Date.now()}`
          needUpdate = true
        }
      }
      if (!data.path) {
        data.path = data.root_id || DEFAULT_ROOT_ID
        needUpdate = true
      }
      if (needUpdate) {
        await this.app.saveDrive(data, { account: data.account })
      }

      this.clientMap[key] = data
    }
  }

  stringify({ path , username , password , cookies }){
    let query = {}
    if(password) query.password = password
    if(cookies) query.cookies = cookies
    return urlFormat({
      protocol: protocol,
      hostname: username,
      pathname: (path == '' ) ? '/' : path,
      slashes:true,
      query,
    })
  }

  async needCaptcha(data, cookie) {
    let resp = await this.app.request.post('https://open.e.189.cn/api/logbox/oauth2/needcaptcha.do', {
      data,
      headers: {
        cookie: cookie,
        referer: 'https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do',
      },
      contentType: 'form',
      responseType: 'text'
    })

    if (resp?.data == '1') {
      return true
    } else {
      return false
    }
  }

  async getCaptcha(captchaToken, reqId, cookie) {
    let resp = await this.app.request(
      `https://open.e.189.cn/api/logbox/oauth2/picCaptcha.do?token=${captchaToken}&REQID=${reqId}&rnd=${Date.now()}`,
      {
        headers: {
          cookie,
          Referer: 'https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do',
        },
        responseType: 'buffer',
      },
    )

    if (resp.error) return { error: resp.error }

    let imgBase64 =
      'data:' + resp.headers['content-type'] + ';base64,' + Buffer.from(resp.data).toString('base64')

    return await this.app.ocr(imgBase64)
  }

  async getSessionKey(cookie) {
    let { data: baseData } = await this.app.request(`https://cloud.189.cn/v2/getUserBriefInfo.action?noCache=${Math.random()}`, {
      headers: {
        cookie,
        // accept: 'application/json;charset=UTF-8'
      },
      responseType: 'json'
    })
    return baseData.sessionKey
  }

  /**
   * refreshCookie
   *
   * @param {object} {account , password}
   * @return {object} { credentials | error }
   * @api private
   */
  async refreshCookie({ path, account, password, cookie_login_user, ...rest }) {

    const { request } = this.app

    if (cookie_login_user) {
      const cookie = `COOKIE_LOGIN_USER=${cookie_login_user};`
      const sessionKey = await this.getSessionKey(cookie)

      return {
        ...rest,
        path : '/'+familyId,
        account,
        password,
        familyId,
        sessionKey,
        cookie,
        updated_at: Date.now(),
      }
    }

    //0 准备工作： 获取必要数据
    let defaultHeaders = { 
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36'
    }
    let { body, headers } = await request.get(`https://cloud.189.cn/unifyLoginForPC.action?appId=8025431004&clientType=10020&returnURL=https%3A%2F%2Fm.cloud.189.cn%2Fzhuanti%2F2020%2FloginErrorPc%2Findex.html&timeStamp=${Date.now()}`, { 
      defaultHeaders,
      responseType: 'text',
    })

    let captchaToken = (body.match(/name='captchaToken' value='(.*?)'>/) || ['', ''])[1],
      returnUrl = (body.match(/returnUrl = '(.*?)'\,/) || ['', ''])[1],
      paramId = (body.match(/var paramId = "(.*?)";/) || ['', ''])[1],
      lt = (body.match(/var lt = "(.*?)";/) || ['', ''])[1],
      reqId = (body.match(/reqId = "(.*?)";/) || ['', ''])[1],
      appKey = (body.match(/appKey = '(.*?)'/) || ['', ''])[1]
    // console.log(headers, pubKey)
    let cookie = headers['set-cookie']

    let formdata = {
      'appKey': appKey,
      'accountType': '02',
      'userName': account,
      'password': password,
      'validateCode': '',
      'captchaToken': captchaToken,
      'returnUrl': returnUrl,
      'mailSuffix': '',
      'dynamicCheck': 'FALSE',
      'clientType': '10020',
      'cb_SaveName': '0',
      'isOauth2': 'false',
      'state': '',
      'paramId': paramId
    }
    // console.log(pubKey, pre, formdata)
    // return this.app.error({ message: 'haha' })
    let retry = 3
    let needcaptcha = await this.needCaptcha(
      {
        accountType: '02',
        userName: account,
        appKey: appKey,
      },
      cookie,
    )

    while (retry--) {
      // 验证码
      if (needcaptcha) {
        let { error, code } = await this.getCaptcha(captchaToken, reqId, cookie)

        if (error) return { error }

        code = code.replace(/\n/g, '')
        if (code.length == 4) {
          formdata.validateCode = code
          console.log('get code', code)
        } else {
          continue
        }

      }

      // 1 登陆
      /*
      let resp = await this.app.request.post('https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do', formdata, {
        headers: {
          'Referer': 'https://cloud.189.cn/udb/udb_login.jsp?pageId=1&redirectURL=/main.action',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36',
          'REQID': reqId,
          'lt': lt,
        },
        json: true
      })
      */
     
      let resp = await request('https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do', {
        headers: {
          'Referer': 'https://cloud.189.cn/udb/udb_login.jsp?pageId=1&redirectURL=/main.action',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36',
          'REQID': reqId,
          'lt': lt,
        },
        data: formdata,
        json: true
      })

      //验证码错误
      if (resp.body.result == -2) {
        console.log('validateCode:[' + formdata.validateCode + '] error')
        continue;
      }

      if (resp.body && !resp.body.toUrl){
        msg = resp.body.msg
        break;
      }

      resp = await request.get(`https://api.cloud.189.cn/getSessionForPC.action?redirectURL=${encodeURIComponent(resp.body.toUrl)}&clientType=TELEPC&version=6.2.5.0&channelId=web_cloud.189.cn`, {
        headers: {
          cookie,
          accept: 'application/json;charset=UTF-8'
        },
        json: true
      })

      let sessionKey = resp.data.familySessionKey
      let sessionSecret = resp.data.familySessionSecret

      //获取 family id
      let date = new Date().toGMTString()
      let signature = hmac(`SessionKey=${sessionKey}&Operate=GET&RequestURI=/family/manage/getFamilyList.action&Date=${date}`,sessionSecret)
      resp = await request.get('https://api.cloud.189.cn/family/manage/getFamilyList.action?clientType=TELEPC&version=6.3.0.0&channelId=web_cloud.189.cn&rand='+Math.random(),{
        headers:{
          'Date':date,
          'SessionKey':sessionKey,
          'Signature': signature,
        },
        responseType: 'text',
      })
      if(!( resp && resp.body && resp.body.includes('<familyId>')) ){
        msg = '无法获取到家庭云'
        break
      }

      let familyId = (resp.body.match(/<familyId>(\d+)<\/familyId>/) || ['',''])[1]

      return {
        ...rest,
        path : '/'+familyId,
        account,
        password,
        familyId,
        sessionKey,
        cookie: sessionSecret,
        updated_at: Date.now(),
      }
    }

    return this.app.error({ message: `Login failed` })
  }

  /**
   * get credentials by client_id
   *
   * @param {string} [id]
   * @return {object}
   * @api public
   */
  async getCredentials(key, force = false) {
    let credentials = this.clientMap[key]

    if (!credentials || !credentials.password || !credentials.account) {
      return { error: { message: 'unmounted' } }
    }

    if (!credentials.cookie || force) {
      credentials = await this.refreshCookie(credentials)
      this.clientMap[key] = { ...credentials }
      await this.app.saveDrive({ key, cookie: credentials.cookie, sessionKey: credentials.sessionKey, familyId : credentials.familyId, path : credentials.path })
    }

    return credentials
  }

  async safeRequest(url, options, retry = 3) {
    let { data, status, headers } = await this.app.request(url, options)

    if (retry > 0 && JSON.stringify(data).includes('InvalidSessionKey')) {
      let key = Object.values(this.clientMap).find((i) => i.cookie === options.headers.cookie)?.account

      if (key) {
        let credentials = await this.getCredentials(key, true)
        options.headers.cookie = credentials.cookie
        return await this.safeRequest(url, options, --retry)
      }
    }

    return { data, status, headers }
  }
}


module.exports = class Driver {
  constructor() {
    this.name = '189CloudHome'
    this.mountable = true
    this.cache = true

    this.version = '1.0'
    this.protocol = protocol

    this.max_age_dir = 30 * 24 * 60 * 60 * 1000 // 7 days

    this.guide = [
      { key: 'account', label: '手机号 / Account', type: 'string', required: true },
      { key: 'password', label: '密码 / Password', type: 'string', required: true },
      { key: 'cookie_login_user', label: 'COOKIE_LOGIN_USER', type: 'string', required: false, help: 'Cookies 中的COOKIE_LOGIN_USER字段，若提供此项则优先使用Cookies登录。' },
      {
        key: 'root_id',
        label: '初始文件夹ID / Root Id',
        help: 'https://cloud.189.cn/web/main/file/folder/xxxx 地址中 xxxx 的部分',
        type: 'string',
      },
    ]
  }

  onReady(app) {
    this.app = app
    this.manager = Manager.getInstance(app)
  }
  async getCredentials(key) {
    return await this.manager.getCredentials(key)
  }

  async fetch(operate = 'GET' , url , credentials , qs) {
    let { sessionKey, cookie } = credentials
    let date = new Date().toGMTString()
    let signature = hmac(`SessionKey=${sessionKey}&Operate=${operate}&RequestURI=${url}&Date=${date}`,cookie)

    let headers = {
      'Date':date,
      'SessionKey': sessionKey,
      'Signature': signature,
      accept: 'application/json;charset=UTF-8',
    }
    let resp
    try{
      resp = await this.app.request(`https://api.cloud.189.cn${url}`, {
        headers,
        method:operate,
        data:qs, 
        async:true,
        responseType: 'text',
      })

      if(resp.error){
        resp.error = resp.error.message[0]
      }
    }catch(e){
      resp = { error:'request error' }
    }

    return resp
    
  }

  /**
   * list children
   *
   * @param {string} [access_token] access_token
   * @param {string} [id] folder id
   * @param {string} [drive_id] drive id
   * @return {array | error}
   *
   * @api public
   */
  async list(id, options, key) {
    const {
      utils: { timestamp },
    } = this.app

    let data = await this.manager.getCredentials(key)

    let { account } = data

    if (!data.sessionKey) return data

    let pathArgs = id.replace(/(^\/|\/$)/,'').split('/')

    let [familyId, folderId = -1, fileId] = pathArgs
    
    let pageNum = 1,
    pageSize = 9999,
      children = []

    do {
      let resp = await this.fetch('GET','/family/file/listFiles.action', data , {
        folderId:folderId == -1 ? '':folderId , 
        familyId, 
        fileType:0,
        iconOption:1,
        mediaAttr:22,
        orderBy:1,
        descending:false,
        pageNum:pageNum,
        pageSize:pageSize,
        clientType:'TELEPC',
        version:'6.3.0.0',
        channelId:'web_cloud.189.cn',
        rand:Math.random()
      })
      
      data = safeJSONParse(resp.data)

      if (data?.errorCode) return this.app.error({ message: data.errorMsg })

      if (data.fileListAO?.folderList) {
        for (let i of data.fileListAO.folderList) {
          children.push({
            id: `${familyId}/` + i.id,
            name: i.name,
            type: 'folder',
            size: i.size,
            ctime: timestamp(i.createDate),
            mtime: timestamp(i.lastOpTime),
            extra: {
              fid: i.id,
              parent_id: i.parentId,
              count: i.fileCount,
            },
          })
        }
      }

      if (data.fileListAO?.fileList) {
        for (let i of data.fileListAO.fileList) {
          children.push({
            id: `${familyId}/${folderId}/` + i.id,
            name: i.name,
            type: 'file',
            size: i.size,
            ctime: timestamp(i.createDate),
            mtime: timestamp(i.lastOpTime),
            extra: {
              fid: i.id,
              parent_id: id,
              md5: i.md5,
            },
          })
        }
      }

      let count = 0
      if(data.fileListAO?.count){
        count = data.fileListAO.count
      }

      if (pageNum * pageSize < count) {
        pageNum++
      } else {
        break
      }
    } while (true)

    return children
  }

  /**
   * get file
   *
   * @param {string} [id] path id
   * @return {object}
   *
   * @api public
   */
  async get(id, key, skipDownloadUrl = false) {

    let data = await this.manager.getCredentials(key)

    let path = this.manager.stringify({username: key, path: id})

    let pathArgs = path.replace(/(^\/|\/$)/,'').split('/')

    let parentId = pathArgs.slice(0,-1).join('/')

    let parentData = await this.manager.app.driver.list({id: parentId})

    let filedata = parentData.files.find(i => i.id == path )

    let resp = await this.fetch('GET','/family/file/getFileDownloadUrl.action',data,{
      familyId : data.familyId,
      fileId : pathArgs.slice(-1),
      clientType:'TELEPC',
      version:'6.3.0.0',
      channelId:'web_cloud.189.cn',
      rand:Math.random()
    })

    resp = safeJSONParse(resp.data.replace(/&amp;/g, '&'))

    if (resp.error) {
      return this.app.error({ message: resp.error })
    }

    let redir = await this.app.request.get(resp.fileDownloadUrl, {
      followRedirect:false ,
      responseType: 'text',
      headers:{
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36',
        //accept: 'application/json;charset=UTF-8',
      },
    })

    console.log(redir.headers.location)

    let result = {download_url: redir.headers.location, ...filedata}
    
    return result
  }
}
