var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Instance Level SSH Only',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensures that instances are not configured to allow project-wide SSH keys',
    more_info: 'To support the principle of least privilege and prevent potential privilege escalation it is recommended that instances are not give access to project-wide SSH keys through instance metadata.',
    link: 'https://cloud.google.com/compute/docs/instances/adding-removing-ssh-keys',
    recommended_action: 'Ensure project-wide SSH keys are blocked for all instances.',
    apis: ['instances:compute:list', 'projects:get'],
    remediation_min_version: '202202270432',
    remediation_description: 'Project-wide SSH keys will be blocked for all virtual machine instances.',
    apis_remediate: ['instances:compute:list', 'projects:get'],
    actions: {remediate:['compute.instances.setMetadata'], rollback:['compute.instances.setMetadata']},
    permissions: {remediate: ['compute.instances.get', 'compute.instances.setMetadata'], rollback: ['compute.instances.get', 'compute.instances.setMetadata']},
    realtime_triggers: ['compute.instances.setMetadata', 'compute.instances.insert'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

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
                    ['instances', 'compute','list', zone]);

                if (!instances) return zcb();

                if (instances.err || !instances.data) {
                    helpers.addResult(results, 3, 'Unable to query compute instances', region, null, null, instances.err);
                    return zcb();
                }

                if (!instances.data.length) {
                    noInstances.push(zone);
                    return zcb();
                }

                instances.data.forEach(instance => {
                    var found;
                    if (instance.metadata &&
                        instance.metadata.items &&
                        instance.metadata.items.length) {
                        found = instance.metadata.items.find(metaItem => metaItem.key === 'block-project-ssh-keys' &&
                            metaItem.value && metaItem.value.toUpperCase() === 'TRUE');
                    }

                    let resource = helpers.createResourceName('instances', instance.name, project, 'zone', zone);
                    if (found) {
                        helpers.addResult(results, 0,
                            'Block project-wide SSH keys is enabled for the instance', region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'Block project-wide SSH keys is disabled for the instance', region, resource);
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
        var pluginName = 'instanceLevelSSHOnly';
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
                        'key': 'block-project-ssh-keys',
                        'value': 'true'
                    });
                } else {
                    items = [{
                        'key': 'block-project-ssh-keys',
                        'value': 'true'
                    }];
                }
                var body = {
                    items,
                    'fingerprint': data.metadata.fingerprint
                };

                // logging
                remediation_file['pre_remediate']['actions'][pluginName][resource] = {
                    'instanceLevelSSHOnly': 'Disabled'
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