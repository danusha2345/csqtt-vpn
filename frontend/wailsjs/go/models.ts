export namespace main {
	
	export class Settings {
	    server: string;
	    password: string;
	    vkLinks: string;
	    workers: number;
	    systemVPN: boolean;
	    excludes: string;
	    obfsMode: string;
	    turnTransport: string;
	
	    static createFrom(source: any = {}) {
	        return new Settings(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.server = source["server"];
	        this.password = source["password"];
	        this.vkLinks = source["vkLinks"];
	        this.workers = source["workers"];
	        this.systemVPN = source["systemVPN"];
	        this.excludes = source["excludes"];
	        this.obfsMode = source["obfsMode"];
	        this.turnTransport = source["turnTransport"];
	    }
	}

}

