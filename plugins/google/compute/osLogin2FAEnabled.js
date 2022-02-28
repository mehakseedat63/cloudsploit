var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'OS Login 2FA Enabled',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensure that Virtual Machines instances have OS logic feature enabled and configured with Two-Factor Authentication.',
    more_info: 'Enable OS login Two-Factor Authentication (2FA) to add an additional security layer to your VM instances. The risk of your VM instances getting attcked is reduced significantly if 2FA is enabled.',
    link: 'https://cloud.google.com/compute/docs/oslogin/setup-two-factor-authentication',
    recommended_action: 'Set enable-oslogin-2fa to true in custom metadata for the instance.',
    apis: ['instances:compute:list', 'projects:get'],
    compliance: {
        pci: 'PCI recommends implementing additional security features for ' +
            'any required service. This includes using secured technologies ' +
            'such as SSH.'
    },
    remediation_min_version: '202202270432',
    remediation_description: 'OS login Two-Factor Authentication (2FA) will be enabled for all virtual machine instances.',
    apis_remediate: ['instances:compute:list', 'projects:get'],
    actions: {remediate:['compute.instances.setMetadata'], rollback:['compute.instances.setMetadata']},
    permissions: {remediate: ['compute.instances.get', 'compute.instances.setMetadata'], rollback: ['compute.instances.get', 'compute.instances.setMetadata']},
    realtime_triggers: ['compute.instances.setMetadata', 'compute.instances.insert'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects', 'get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0].name;

        async.each(regions.instances.compute, (region, rcb) => {
            var zones = regions.zones;
            var noInstances = [];
            async.each(zones[region], function(zone, zcb) {
                var instances = helpers.addSource(cache, source,
                    ['instances', 'compute', 'list', zone]);

                if (!instances) return zcb();

                if (instances.err || !instances.data) {
                    helpers.addResult(results, 3, 'Unable to query instances', region, null, null, instances.err);
                    return zcb();
                }

                if (!instances.data.length) {
                    noInstances.push(zone);
                    return zcb();
                }

                instances.data.forEach(instance => {
                    let resource = helpers.createResourceName('instances', instance.name, project, 'zone', zone);
                    let isEnabled = false;

                    if (instance.metadata && instance.metadata.items && instance.metadata.items.length) {

                        if (instance.metadata.items.find(item => (item.key && item.key.toLowerCase() === 'enable-oslogin-2fa' &&
                            item.value && item.value.toLowerCase() === 'true'))) {
                            isEnabled = true;
                        }
                    }

                    if (isEnabled) {
                        helpers.addResult(results, 0,
                            'OS Login 2FA is enabled for the the instance', region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'OS Login 2FA is not enabled for the the instance', region, resource);
                    }

                });
                zcb();
            }, function() {
                if (noInstances.length) {
                    helpers.addResult(results, 0, `No instances found in following zones: ${noInstances.join(', ')}`, region);
                }
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    },
    remediate: function(config, cache, settings, resource, callback) {
        var remediation_file = settings.remediation_file;
        var pluginName = 'osLogin2FAEnabled';
        var baseUrl = 'https://compute.googleapis.com/compute/v1/{resource}/setMetadata';
        var method = 'POST';
        var putCall = this.actions.remediate;

        //get the resource first because we need finger print to set metadata
        var getUrl = `https://compute.googleapis.com/compute/v1/${resource}`;
        helpers.getResource(config, getUrl, function(err, data) {
            if (err) return callback(err);
            if (data) {
                // create the params necessary for the remediation

                //adding to existing metadata values if they exist
                let items = data.metadata && data.metadata.items;
                if (items && items.length) {
                    items.push({
                        'key': 'enable-oslogin-2fa',
                        'value': 'true'
                    });
                } else {
                    items = [{
                        'key': 'enable-oslogin-2fa',
                        'value': 'true'
                    }];
                }
                var body = {
                    items,
                    'fingerprint': data.metadata.fingerprint
                };

                // logging
                remediation_file['pre_remediate']['actions'][pluginName][resource] = {
                    'osLogin2FA': 'Disabled'
                };

                helpers.remediatePlugin(config, method, body, baseUrl, resource, remediation_file, putCall, pluginName, function(err, action) {
                    if (err) return callback(err);
                    if (action) action.action = putCall;


                    remediation_file['post_remediate']['actions'][pluginName][resource] = action;
                    remediation_file['remediate']['actions'][pluginName][resource] = {
                        'Action': 'Enabled'
                    };

                    callback(null, action);
                });
            }
        });
    }
};