from sre_constants import IN_LOC_IGNORE

from support_diagnostics import Analyzer, AnalyzerResult, AnalyzerResultSeverityInfo, AnalyzerResultSeverityPass, AnalyzerResultSeverityWarn, AnalyzerResultSeverityFail
from support_diagnostics import Configuration, ImportModules

ImportModules.import_all(globals(), "collectors")
class IpsecAnalyzer(Analyzer):
    """
    Analyze file system entries for size.
    """
    order = 0
    
    heading = "IPSec Interfaces"
    categories = ["ipsec"]
    collector = [IpXfrmPolicyCollector, IpXfrmStateCollector, IpTunnelCollector, IpsecStatusAllCollector, SettingsCollector]

    results = {
        "info": AnalyzerResult(
                severity=AnalyzerResultSeverityInfo,
                summary="Info for you...",
        ),
        "tunnel": AnalyzerResult(
                severity=AnalyzerResultSeverityPass,
                other_results={
                    "{severity}": "Tunnel found from 'ip -s tunnel', local={local_gateway}",
                }
        ),
        "no_tunnel": AnalyzerResult(
                severity=AnalyzerResultSeverityFail,
                summary="No tunnel found",
                detail="Cannot find tunnel",
                recommendation="Fix configuration"
        ),
        "policy": AnalyzerResult(
                severity=AnalyzerResultSeverityPass,
                other_results={
                    "{severity}": "Matching 'ip xfrm policy' found count={count}",
                }
        ),
        "no_policy": AnalyzerResult(
                severity=AnalyzerResultSeverityFail,
                summary="No policies found",
                detail="Cannot find policies in ip xfrm policy",
                recommendation=[
                    "Tunnel gateway address may not be reachable",
                    "Local and/or Remote networks may be mismatches",
                    "Authentication may be mismatched",
                    "Phase 1 ciphers may be mismatches"
                ]
        ),
        "state": AnalyzerResult(
                severity=AnalyzerResultSeverityPass,
                other_results={
                    "{severity}": "Matching 'ip xfrm state' found count={count}",
                }
        ),
        "no_state": AnalyzerResult(
                severity=AnalyzerResultSeverityFail,
                summary="No states found",
                detail="Cannot find states",
                recommendation="Possibly another system is connection on remote"
        ),
        "status": AnalyzerResult(
                severity=AnalyzerResultSeverityPass,
                other_results={
                    "{severity}": "Matcing 'ipsec statusall' found",
                }
        ),
        "no_status": AnalyzerResult(
                severity=AnalyzerResultSeverityFail,
                summary="No status found",
                detail="Cannot find status",
                recommendation="Possibly bad cipher suites"
        ),

        "wan_routing": AnalyzerResult(
                severity=AnalyzerResultSeverityPass,
                other_results={
                    "{severity}": "Matching WAN routing found",
                }
        ),
        "no_wan_routing": AnalyzerResult(
                severity=AnalyzerResultSeverityFail,
                summary="No WAN routing found",
                detail="Cannot find WAN rules + policies for interface traffic.",
                recommendation="Review WAN Rules and WAN Rules order"
        )

    }

    def analyze(self, collector_results):
        results = []

        tunnels = self.get_tunnels(collector_results)
        for tunnel in tunnels:
            # print(tunnel)
            # Walk collector results, and get matches based on settings config
            local_gateway = tunnel.get("ipsec").get("local").get("gateway")
            local_networks = tunnel.get("ipsec").get("local").get("networks")
            remote_gateway = tunnel.get("ipsec").get("remote").get("gateway")
            remote_networks = tunnel.get("ipsec").get("remote").get("networks")
            result = AnalyzerResult(severity=AnalyzerResultSeverityInfo,other_results={\
                "{severity}" : ['name={name}, local={local_gateway} ({local_networks}), remote={remote_gateway} ({local_networks})',\
                                'auth={auth}, phase1={phase1}, phase2={phase2}']
            })
            format_fields = {
                'name': tunnel.get("name"),
                'local_gateway': local_gateway,
                'local_networks': ",".join( f"{n.get('network')}/{n.get('prefix')}" for n in local_networks),
                'remote_gateway': remote_gateway,
                'remote_networks': ",".join( f"{n.get('network')}/{n.get('prefix')}" for n in remote_networks),
                'auth': tunnel.get("ipsec").get("authentication").get("type"),
                'phase1': ",".join( f"{n.get('encryption')}-{n.get('hash')}-{n.get('group')}" for n in tunnel.get("ipsec").get("phase1")),
                'phase2': ",".join( f"{n.get('encryption')}-{n.get('hash')}-{n.get('group')}" for n in tunnel.get("ipsec").get("phase1")),
            }
            result.analyzer = self
            result.format(format_fields)
            results.append(result)

            if tunnel.get("enabled") is False:
                result = AnalyzerResult(severity=AnalyzerResultSeverityWarn,other_results={ \
                    "{severity}" : 'Disabled'
                })
                result.analyzer = self
                result.format()
                results.append(result)
                continue

            tunnel_collector = None
            policy_collector = None
            state_collector = None
            status_collector = None
            for collector_result in collector_results:
                if collector_result.collector.__class__ is IpTunnelCollector:
                    if collector_result.output.get("remote") == remote_gateway:
                        tunnel_collector = collector_result
                elif collector_result.collector.__class__ is IpXfrmPolicyCollector:
                    if "tunnel" in collector_result.output and \
                        (collector_result.output.get("tunnel").get("src") == remote_gateway or \
                         collector_result.output.get("tunnel").get("dst") == remote_gateway):
                        if policy_collector is None:
                            policy_collector = []
                        policy_collector.append(collector_result)
                elif collector_result.collector.__class__ is IpXfrmStateCollector:
                    if (collector_result.output.get("src") == remote_gateway or
                         collector_result.output.get("dst") == remote_gateway):
                        if state_collector is None:
                            state_collector = []
                        state_collector.append(collector_result)
                elif collector_result.collector.__class__ is IpsecStatusAllCollector and \
                    collector_result.source == "connections":
                    for id in collector_result.output:
                        if id is None:
                            continue
                        if "remote" in collector_result.output.get(id) and \
                            "gateway" in collector_result.output.get(id).get("remote") and \
                            collector_result.output.get(id).get("remote").get("gateway") == remote_gateway:
                            status_collector = collector_result.output

            if tunnel_collector is None:
                result = IpsecAnalyzer.results['no_tunnel'].copy()
            
                result.collector_result = tunnel_collector
                result.analyzer = self
                results.append(result)
                continue
            else:
                result = IpsecAnalyzer.results['tunnel'].copy()
                if tunnel_collector.output.get("local") != local_gateway:
                    result.severity = AnalyzerResultSeverityWarn
            
                result.collector_result = tunnel_collector
                result.analyzer = self
                format_fields = {
                    'local_gateway': tunnel_collector.output.get("local"),
                }
                result.format(format_fields)
                results.append(result)

            if policy_collector is None:
                result = IpsecAnalyzer.results['no_policy'].copy()
            
                result.collector_result = tunnel_collector
                result.analyzer = self
                results.append(result)
                continue
            else:
                # Count of results is important!  At least 3 (2 x for gw, 1x for tunnel)
                result = IpsecAnalyzer.results['policy'].copy()            
                result.collector_result = policy_collector
                result.analyzer = self
                result.format({
                    "count": len(policy_collector)
                })
                results.append(result)

            if state_collector is None:
                result = IpsecAnalyzer.results['no_state'].copy()
            
                result.collector_result = state_collector
                result.analyzer = self
                results.append(result)
                continue
            else:
                result = IpsecAnalyzer.results['state'].copy()
            
                result.collector_result = state_collector
                result.analyzer = self
                result.format({
                    "count": len(state_collector)
                })
                results.append(result)

            if status_collector is None:
                result = IpsecAnalyzer.results['no_status'].copy()
            
                result.collector_result = tunnel_collector
                result.analyzer = self
                results.append(result)
                continue
            else:
                result = IpsecAnalyzer.results['status'].copy()
            
                result.collector_result = tunnel_collector
                result.analyzer = self
                result.format()
                results.append(result)

            wan_policies = self.get_wan_policies_for_interface(collector_results, tunnel.get("interfaceId"))
            wan_rules = self.get_wan_rules_for_policies(collector_results, tunnel, wan_policies)
            if len(wan_rules) == 0:
                result = IpsecAnalyzer.results['no_wan_routing'].copy()
            
                result.collector_result = tunnel_collector
                result.analyzer = self
                results.append(result)
                continue
            else:
                result = IpsecAnalyzer.results['wan_routing'].copy()
            
                result.collector_result = tunnel_collector
                result.analyzer = self
                result.format()
                results.append(result)
            
        return results

    def get_tunnels(self, collector_results):
        """
        """
        tunnels = []
        for collector_result in collector_results:
            if collector_result.collector.__class__ is SettingsCollector:
                for interface in collector_result.output.get("network").get("interfaces"):
                    if interface.get("type") == "IPSEC":
                        tunnels.append(interface)
        return tunnels

    def get_wan_policies_for_interface(self, collector_results, interfaceId):
        """
        """
        policies = []
        for collector_result in collector_results:
            if collector_result.collector.__class__ is SettingsCollector:
                for policy in collector_result.output.get("wan").get("policies"):
                    if policy.get("enabled") == False:
                        continue
                    for interface in policy.get("interfaces"):
                        if interface.get("interfaceId") == interfaceId or \
                            interface.get("interfaceId") == 0:
                            policies.append(policy)

        return policies

    def get_wan_rules_for_policies(self, collector_results, interface, policies):
        """
        Get wan rules for the specified interface that are tied to policies.
        """        
        specific_policy_ids = []
        for policy in policies:
            if policy.get("type") != "SPECIFIC_WAN":
                continue
            for policy_interface in policy.get("interfaces"):
                if policy_interface.get("interfaceId") == interface.get("interfaceId"):
                    specific_policy_ids.append(policy.get("policyId"))

        rules = []
        for collector_result in collector_results:
            if collector_result.collector.__class__ is SettingsCollector:
                for chain in collector_result.output.get("wan").get("policy_chains"):
                    found_rule_default = False
                    for rule in chain.get("rules"):
                        if rule.get("enabled") == False:
                            continue

                        in_policy = False
                        for policy in policies:
                            if policy.get("policyId") == rule.get("action").get("policy"):
                                in_policy = True

                        if in_policy == False:
                            continue

                        in_remote_network = False
                        conditions = rule.get("conditions")
                        if len(conditions) == 0:
                            conditions.append({
                                "type": "DESTINATION_ADDRESS",
                                "op": "==",
                                "value": "0.0.0.0/0"
                            })
                        for rule_condition in conditions:
                            if rule_condition.get("type") == "DESTINATION_ADDRESS" and \
                                rule_condition.get("op") == "==":
                                if found_rule_default == True:
                                    # Already seen a default rule so don't bother comparing
                                    continue
                                if rule_condition.get("value") == "0.0.0.0/0":
                                    # We've found a default route rule.
                                    # No rule after this will match! 
                                    found_rule_default = True

                                for network in interface.get("ipsec").get("remote").get("networks"):
                                    if rule_condition.get("value") == f"{network.get('network')}/{network.get('prefix')}":
                                        if rule.get("action").get("policy") in specific_policy_ids:
                                            in_remote_network = True
                        
                        if in_remote_network == True:
                            rules.append(rule)

        return rules