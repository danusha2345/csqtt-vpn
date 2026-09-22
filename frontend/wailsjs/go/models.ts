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
	    vkHashMode: string;
	    vkToken: string;
	
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
	        this.vkHashMode = source["vkHashMode"];
	        this.vkToken = source["vkToken"];
	    }
	}
	export class VersionInfo {
	    desktop: string;
	    core: string;
	    compatibility: string;
	
	    static createFrom(source: any = {}) {
	        return new VersionInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.desktop = source["desktop"];
	        this.core = source["core"];
	        this.compatibility = source["compatibility"];
	    }
	}

}

export namespace updater {
	
	export class Asset {
	    name: string;
	    size: number;
	    digest: string;
	
	    static createFrom(source: any = {}) {
	        return new Asset(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.size = source["size"];
	        this.digest = source["digest"];
	    }
	}
	export class Candidate {
	    version: string;
	    notes: string;
	    compatibility: string;
	
	    static createFrom(source: any = {}) {
	        return new Candidate(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.version = source["version"];
	        this.notes = source["notes"];
	        this.compatibility = source["compatibility"];
	    }
	}

}

