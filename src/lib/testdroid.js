require('6to5/polyfill');
import Debug from 'debug';
import request from 'superagent-promise';
import url from 'url';
import util from 'util';

let debug = Debug('taskcluster-testdroid');
let VERSION = require('../../package.json').version;

export default class {
  constructor(url, username, password) {
    this.version = VERSION;
    this.baseUrl = url;
    this.apiUrl = url + 'api/v2/';
    this.username = username;
    this.password = password;
    this.defaultHeaders = {
      'User-Agent': 'taskcluster-bitbar/' + this.version,
      'Accept': 'application/json'
    };
  }

  async buildHeaders(additionalHeaders) {
    let headers = typeof(additionalHeaders) !== 'undefined' ? additionalHeaders : {};
    let token = await this.getToken();
    headers.Authorization = `Bearer ${token}`;
    headers.Accept = 'application/json';
    return headers;
  }

  async get(path, opts) {
    debug("Retrieving %s with opts: %j", path, opts);
    let endpoint = url.resolve(this.apiUrl, path);
    let headers = await this.buildHeaders();
    let r = request.get(endpoint);
    r.set(headers);

    if ('queryString' in opts) {
      r.query(opts.queryString);
    }

    let res = await r.end();

    if (!res.ok) {
      throw new Error("Reqeust no bueno");
    }
    return res.body.data;
  }

  async getDevices(limit) {
    let deviceLimit = typeof(limit) !== 'undefined' ? limit : 0;
    let opts = { 'queryString': { 'limit': deviceLimit }};
    let devices = await this.get('devices', opts);
    return devices;
  }

  async getToken() {
    let authUrl = url.resolve(this.baseUrl, 'oauth/token');
    let payload;
    if (!this.token || Date.now() > this.tokenExpiration) {
      debug('requesting new token');
      payload = {
        'client_id': 'testdroid-cloud-api',
        'grant_type': 'password',
        'username': this.username,
        'password': this.password
      };
    } else {
      // TODO only refresh if expiration is close (10 seconds?)
      debug('refreshing token');
      payload = {
        'client_id': 'testdroid-cloud-api',
        'grant_type': 'refresh_token',
        'refresh_token': this.refreshToken
      };
    }

    var res = await request
                .post(authUrl)
                .type('form')
                .set(this.defaultHeaders)
                .send(payload)
                .end();

    if (!res.ok) {
      throw new Error(
        util.format("Could not get token. " +
                    "Error Reponse: %s", res.body.error_description)
      );
    }
    this.refreshToken = res.body.refresh_token;
    this.token = res.body.access_token;
    this.tokenExpiration = new Date(Date.now() + res.body.expires_in);
    return res.body.access_token;
  }
}

