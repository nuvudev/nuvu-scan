"""
HTML report formatter.
"""

from ...core import ScanResult


class HTMLFormatter:
    """Formats scan results as HTML report."""

    def format(self, result: ScanResult) -> str:
        """Format scan result as HTML."""
        # Build summary cards (use actual cost if available)
        actual_total = result.summary.get("total_actual_cost_30d")
        estimated_assets_total = result.summary.get("estimated_assets_cost_total")

        # Calculate cost saving opportunities
        savings_opportunities = self._calculate_savings(result.assets)

        summary_cards = f"""
            <div class="summary-card">
                <h3>Total Assets</h3>
                <div class="value">{len(result.assets)}</div>
            </div>
        """

        if actual_total is not None:
            summary_cards += f"""
            <div class="summary-card">
                <h3>Actual 30-Day Cost</h3>
                <div class="value">${actual_total:,.2f}</div>
            </div>
            <div class="summary-card">
                <h3>Estimated Asset Cost</h3>
                <div class="value">${(estimated_assets_total or 0):,.2f}</div>
            </div>
            """
        else:
            summary_cards += f"""
            <div class="summary-card">
                <h3>Estimated Monthly Cost</h3>
                <div class="value">${result.total_cost_estimate_usd:,.2f}</div>
            </div>
            """

        summary_cards += f"""
            <div class="summary-card">
                <h3>Unused Assets</h3>
                <div class="value">{result.summary.get("unused_count", 0)}</div>
            </div>
            <div class="summary-card">
                <h3>No Owner</h3>
                <div class="value">{result.summary.get("no_owner_count", 0)}</div>
            </div>
            <div class="summary-card">
                <h3>Risky Assets</h3>
                <div class="value">{result.summary.get("risky_count", 0)}</div>
            </div>
        """

        # Add savings opportunity card if significant
        if savings_opportunities["total_potential_savings"] > 100:
            summary_cards += f"""
            <div class="summary-card savings">
                <h3>💰 Potential Savings</h3>
                <div class="value">${savings_opportunities["total_potential_savings"]:,.2f}/mo</div>
            </div>
            """

        # Build service costs table if available
        service_costs_html = ""
        service_costs = result.summary.get("actual_costs_30d", {})
        if service_costs:
            # Sort by cost descending
            sorted_services = sorted(service_costs.items(), key=lambda x: x[1], reverse=True)
            rows = "\n".join(
                f"            <tr><td>{service}</td><td>${cost:,.2f}</td></tr>"
                for service, cost in sorted_services
            )
            service_costs_html = f"""
        <h2>Service Costs (Last 30 Days)</h2>
        <table>
            <tr><th>Service</th><th>Cost (USD)</th></tr>
{rows}
        </table>
            """

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Nuvu Scan Report - {result.provider.upper()}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin: 20px 0; }}
        .summary-card {{ background: #f9f9f9; padding: 15px; border-radius: 5px; border-left: 4px solid #4CAF50; }}
        .summary-card.savings {{ border-left-color: #ff9800; background: #fff8e1; }}
        .summary-card h3 {{ margin: 0 0 10px 0; color: #666; font-size: 13px; text-transform: uppercase; }}
        .summary-card .value {{ font-size: 22px; font-weight: bold; color: #333; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        table.compact {{ font-size: 13px; }}
        table.compact th, table.compact td {{ padding: 8px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #4CAF50; color: white; font-weight: bold; }}
        tr:hover {{ background: #f5f5f5; }}
        .risk-flag {{ display: inline-block; background: #ff4444; color: white; padding: 3px 8px; border-radius: 3px; font-size: 11px; margin: 2px; }}
        .unused {{ color: #ff8800; font-weight: bold; }}
        .no-owner {{ color: #ff4444; font-weight: bold; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; text-align: center; }}
        .insight-box {{ padding: 15px; border-radius: 8px; margin: 15px 0; }}
        .insight-box h3 {{ margin-top: 0; }}
        .insight-box.warning {{ background: #fff8e1; border-left: 4px solid #ff9800; }}
        .insight-box.alert {{ background: #ffebee; border-left: 4px solid #f44336; }}
        .insight-box.info {{ background: #e3f2fd; border-left: 4px solid #2196f3; }}
        .insight-box.success {{ background: #e8f5e9; border-left: 4px solid #4caf50; }}
        .recommendation {{ font-style: italic; color: #666; margin-top: 10px; }}
        /* Collapsible sections */
        .collapsible {{ cursor: pointer; padding: 15px; width: 100%; border: none; text-align: left; outline: none; font-size: 18px; font-weight: bold; background: #f5f5f5; border-radius: 5px; margin-top: 20px; color: #555; display: flex; justify-content: space-between; align-items: center; }}
        .collapsible:hover {{ background: #eee; }}
        .collapsible:after {{ content: '▼'; font-size: 12px; color: #888; }}
        .collapsible.active:after {{ content: '▲'; }}
        .collapsible-content {{ display: none; overflow: hidden; padding: 0; }}
        .collapsible-content.show {{ display: block; }}
        .asset-count {{ font-size: 14px; font-weight: normal; color: #888; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Nuvu Scan Report</h1>
        <p><strong>Provider:</strong> {result.provider.upper()}</p>
        <p><strong>Account ID:</strong> {result.account_id}</p>
        <p><strong>Scan Time:</strong> {result.scan_timestamp}</p>

        <h2>📋 Scan Scope</h2>
        <div class="insight-box info">
            <p><strong>Collectors:</strong> {", ".join(result.scanned_collectors) if result.scanned_collectors else "All (Full Scan)"}</p>
            <p><strong>Regions:</strong> {", ".join(result.scanned_regions[:10]) if result.scanned_regions else "All enabled regions"}{" (+ " + str(len(result.scanned_regions) - 10) + " more)" if len(result.scanned_regions) > 10 else ""}</p>
        </div>

        <h2>Executive Summary</h2>
        <div class="summary">
{summary_cards}
        </div>
{service_costs_html}
"""

        # Add Cost Optimization Section FIRST (before Assets by Category)
        html += self._build_cost_optimization_section(result.assets)

        # Add Governance Insights Section SECOND
        html += self._build_governance_section(result.assets)

        # Assets by Category
        html += """
        <h2>Assets by Category</h2>
        <table>
            <tr><th>Category</th><th>Count</th></tr>
"""

        for category, count in result.summary.get("assets_by_category", {}).items():
            html += f"            <tr><td>{category.replace('_', ' ').title()}</td><td>{count}</td></tr>\n"

        # All Assets - COLLAPSIBLE
        # Filter out:
        # - Expired/retired reserved nodes (historical clutter)
        # - Cost summary (it's a summary row, not an asset)
        # They're still counted in the governance summary for context
        display_assets = [
            a
            for a in result.assets
            if not (
                # Exclude expired/retired reserved nodes
                (
                    a.asset_type == "redshift_reserved_node"
                    and any(
                        flag in (a.risk_flags or [])
                        for flag in ["reservation_expired", "reservation_retired"]
                    )
                )
                # Exclude cost summary pseudo-asset
                or a.asset_type == "cost_summary"
            )
        ]
        asset_count = len(display_assets)
        html += f"""        </table>

        <button class="collapsible">All Assets <span class="asset-count">({asset_count} items)</span></button>
        <div class="collapsible-content">
        <table>
            <tr>
                <th>Name</th>
                <th>Service</th>
                <th>Type</th>
                <th>Region</th>
                <th>Cost (USD/mo)</th>
                <th>Owner</th>
                <th>Risks</th>
            </tr>
"""

        # Sort assets by cost (descending)
        sorted_assets = sorted(display_assets, key=lambda x: x.cost_estimate_usd or 0, reverse=True)

        for asset in sorted_assets:
            owner_class = ""
            # Only show no-owner class if we have no suggested owner at all
            if not asset.suggested_owner and asset.ownership_confidence == "unknown":
                owner_class = "no-owner"

            risk_flags_html = ""
            if asset.risk_flags:
                for flag in asset.risk_flags:
                    risk_flags_html += f'<span class="risk-flag">{flag}</span>'

            html += f"""            <tr>
                <td>{asset.name}</td>
                <td>{asset.service}</td>
                <td>{asset.asset_type}</td>
                <td>{asset.region}</td>
                <td>${asset.cost_estimate_usd or 0:.2f}</td>
                <td class="{owner_class}">{asset.suggested_owner or "Unknown"}</td>
                <td>{risk_flags_html}</td>
            </tr>
"""

        html += """        </table>
        </div>

        <script>
        var coll = document.getElementsByClassName("collapsible");
        for (var i = 0; i < coll.length; i++) {
            coll[i].addEventListener("click", function() {
                this.classList.toggle("active");
                var content = this.nextElementSibling;
                content.classList.toggle("show");
            });
        }
        </script>

        <div class="footer">
            <p>Generated by <strong>nuvu-scan</strong> — Open Source Data Governance Scanner</p>
            <p><a href="https://github.com/nuvudev/nuvu-scan" target="_blank">github.com/nuvudev/nuvu-scan</a></p>
            <p style="margin-top: 10px; font-size: 11px; color: #999;">Want historical tracking, team collaboration, and scheduled scans? Try <a href="https://nuvu.dev" style="color: #888;">Nuvu Cloud</a></p>
        </div>
    </div>
</body>
</html>"""

        return html

    def _calculate_savings(self, assets) -> dict:
        """Calculate potential cost savings from assets."""
        savings = {
            "old_manual_snapshots": 0,
            "stale_crawlers": 0,
            "unused_etl_jobs": 0,
            "reservation_opportunities": 0,
            "total_potential_savings": 0,
        }

        for asset in assets:
            metrics = asset.usage_metrics or {}

            # Old MANUAL snapshot savings (automated snapshots are free within retention)
            if asset.asset_type == "redshift_snapshot":
                if metrics.get("snapshot_type") == "manual":
                    if "old_snapshot" in (asset.risk_flags or []):
                        savings["old_manual_snapshots"] += asset.cost_estimate_usd or 0

            # Reservation savings
            if asset.asset_type == "redshift_cluster":
                potential = metrics.get("potential_reservation_savings_usd", 0)
                savings["reservation_opportunities"] += potential

            # Stale crawler costs
            if asset.asset_type == "glue_crawler":
                if "stale_crawler" in (asset.risk_flags or []):
                    savings["stale_crawlers"] += asset.cost_estimate_usd or 0

        savings["total_potential_savings"] = (
            savings["old_manual_snapshots"]
            + savings["reservation_opportunities"]
            + savings["stale_crawlers"]
        )

        return savings

    def _build_cost_optimization_section(self, assets) -> str:
        """Build cost optimization recommendations section."""
        # Filter relevant assets
        snapshots = [a for a in assets if a.asset_type == "redshift_snapshot"]
        manual_snapshots = [
            a for a in snapshots if (a.usage_metrics or {}).get("snapshot_type") == "manual"
        ]
        auto_snapshots = [
            a for a in snapshots if (a.usage_metrics or {}).get("snapshot_type") == "automated"
        ]
        old_manual_snapshots = [
            a for a in manual_snapshots if "old_snapshot" in (a.risk_flags or [])
        ]
        reserved_nodes = [a for a in assets if a.asset_type == "redshift_reserved_node"]
        expiring_reservations = [
            a for a in reserved_nodes if "reservation_expiring_soon" in (a.risk_flags or [])
        ]

        if not snapshots and not reserved_nodes:
            return ""

        html = """
        <h2>💰 Cost Optimization Opportunities</h2>
        """

        # Snapshot analysis - only manual snapshots are chargeable
        if snapshots:
            manual_snapshot_cost = sum(a.cost_estimate_usd or 0 for a in manual_snapshots)
            old_manual_cost = sum(a.cost_estimate_usd or 0 for a in old_manual_snapshots)
            manual_size = sum((a.size_bytes or 0) / (1024**4) for a in manual_snapshots)  # TB

            html += f"""
        <div class="insight-box warning">
            <h3>📦 Redshift Snapshots</h3>
            <ul>
                <li><strong>Automated Snapshots:</strong> {len(auto_snapshots)} (included in cluster cost)</li>
                <li><strong>Manual Snapshots:</strong> {len(manual_snapshots)} ({manual_size:.2f} TB)</li>
                <li><strong>Manual Snapshot Cost:</strong> ${manual_snapshot_cost:,.2f}/mo</li>
                <li><strong>Old Manual Snapshots (>90 days):</strong> {len(old_manual_snapshots)} (${old_manual_cost:,.2f}/mo potential savings)</li>
            </ul>
            <p class="recommendation">💡 Review old manual snapshots - automated snapshots are retained per retention policy at no extra charge.</p>
        </div>
            """

        # Reserved nodes analysis - compare with provisioned clusters
        if reserved_nodes:
            active_reservations = [
                a for a in reserved_nodes if (a.usage_metrics or {}).get("state") == "active"
            ]

            # Count total nodes covered by active reservations
            active_reserved_nodes = sum(
                (a.usage_metrics or {}).get("node_count", 0) for a in active_reservations
            )

            # Count total provisioned cluster nodes
            clusters = [a for a in assets if a.asset_type == "redshift_cluster"]
            total_provisioned_nodes = sum(
                (a.usage_metrics or {}).get("node_count", 0) for a in clusters
            )

            # Calculate uncovered nodes (potential savings opportunity)
            uncovered_nodes = max(0, total_provisioned_nodes - active_reserved_nodes)

            # Determine if this is a savings opportunity
            is_savings_opportunity = uncovered_nodes > 0
            box_class = "warning" if is_savings_opportunity else "info"

            html += f"""
        <div class="insight-box {box_class}">
            <h3>🎫 Reserved vs On-Demand Nodes</h3>
            <ul>
                <li><strong>Provisioned Cluster Nodes:</strong> {total_provisioned_nodes}</li>
                <li><strong>Active Reserved Nodes:</strong> {active_reserved_nodes} ({len(active_reservations)} reservations)</li>
                <li><strong>Uncovered (On-Demand) Nodes:</strong> {uncovered_nodes}</li>
            </ul>
            """

            if is_savings_opportunity:
                # Estimate savings: reserved pricing saves ~30-40% on average
                # Rough estimate: $500/node/month on-demand vs $300/node/month reserved
                estimated_monthly_savings = (
                    uncovered_nodes * 200
                )  # Conservative $200/node/month savings
                html += f"""
            <p class="recommendation">💰 <strong>Potential Savings:</strong> {uncovered_nodes} nodes running on-demand pricing. Consider purchasing reserved nodes to save ~${estimated_monthly_savings:,.0f}/month (estimated 30-40% discount).</p>
            """
            else:
                html += """
            <p class="recommendation">✅ All provisioned nodes are covered by reservations.</p>
            """

            # Show expiring reservations if any
            if expiring_reservations:
                expiring_nodes = sum(
                    (a.usage_metrics or {}).get("node_count", 0) for a in expiring_reservations
                )
                html += f"""
            <p class="recommendation">⚠️ <strong>{len(expiring_reservations)} reservations ({expiring_nodes} nodes) expiring soon.</strong> Plan for renewal to maintain coverage.</p>
            """

            html += "</div>"

        return html

    def _build_governance_section(self, assets) -> str:
        """Build governance insights section."""
        # Glue crawlers
        crawlers = [a for a in assets if a.asset_type == "glue_crawler"]
        stale_crawlers = [
            a
            for a in crawlers
            if "stale_crawler" in (a.risk_flags or []) or "never_run" in (a.risk_flags or [])
        ]

        # Glue jobs
        jobs = [a for a in assets if a.asset_type == "glue_job"]
        stale_jobs = [
            a
            for a in jobs
            if "stale_job" in (a.risk_flags or []) or "never_run" in (a.risk_flags or [])
        ]

        # Datashares
        datashares = [a for a in assets if a.asset_type == "redshift_datashare"]
        cross_account_shares = [
            a for a in datashares if "cross_account_sharing" in (a.risk_flags or [])
        ]

        # WLM issues
        clusters = [a for a in assets if a.asset_type == "redshift_cluster"]
        wlm_issues = [
            a
            for a in clusters
            if "default_wlm_only" in (a.risk_flags or [])
            or "unlimited_wlm_queue" in (a.risk_flags or [])
        ]

        if not any([stale_crawlers, stale_jobs, cross_account_shares, wlm_issues]):
            return ""

        html = """
        <h2>🔍 Governance Insights</h2>
        """

        if stale_crawlers:
            html += f"""
        <div class="insight-box warning">
            <h3>🕷️ Stale/Unused Glue Crawlers ({len(stale_crawlers)})</h3>
            <table class="compact">
                <tr><th>Name</th><th>Last Run</th><th>Issue</th></tr>
            """
            for crawler in stale_crawlers[:10]:
                days = (crawler.usage_metrics or {}).get("days_since_last_run", "Never")
                issues = ", ".join(crawler.risk_flags or [])
                html += f"<tr><td>{crawler.name}</td><td>{days} days ago</td><td>{issues}</td></tr>"
            html += "</table></div>"

        if stale_jobs:
            html += f"""
        <div class="insight-box warning">
            <h3>⚙️ Stale/Unused Glue ETL Jobs ({len(stale_jobs)})</h3>
            <table class="compact">
                <tr><th>Name</th><th>Last Run</th><th>Issue</th></tr>
            """
            for job in stale_jobs[:10]:
                days = (job.usage_metrics or {}).get("days_since_last_run", "Never")
                issues = ", ".join(job.risk_flags or [])
                html += f"<tr><td>{job.name}</td><td>{days} days ago</td><td>{issues}</td></tr>"
            html += "</table></div>"

        if cross_account_shares:
            html += f"""
        <div class="insight-box alert">
            <h3>🔗 Cross-Account Data Shares ({len(cross_account_shares)})</h3>
            <p>Data is being shared outside this AWS account. Review for security compliance.</p>
            <table class="compact">
                <tr><th>Share Name</th><th>Consumer Account</th><th>Flags</th></tr>
            """
            for share in cross_account_shares[:10]:
                consumers = (share.usage_metrics or {}).get("consumers", [])
                consumer_ids = ", ".join(c.get("account_id", "?") for c in consumers[:3])
                flags = ", ".join(share.risk_flags or [])
                html += f"<tr><td>{share.name}</td><td>{consumer_ids}</td><td>{flags}</td></tr>"
            html += "</table></div>"

        if wlm_issues:
            html += f"""
        <div class="insight-box info">
            <h3>⚡ WLM Configuration Review ({len(wlm_issues)} clusters)</h3>
            <p>Some clusters may benefit from WLM tuning:</p>
            <ul>
            """
            for cluster in wlm_issues[:5]:
                queues = (cluster.usage_metrics or {}).get("wlm_queue_count", 0)
                auto_wlm = "Yes" if (cluster.usage_metrics or {}).get("wlm_auto_wlm") else "No"
                flags = ", ".join(f for f in (cluster.risk_flags or []) if "wlm" in f)
                html += f"<li><strong>{cluster.name}</strong>: {queues} queues, Auto WLM: {auto_wlm} ({flags})</li>"
            html += "</ul></div>"

        # Add cluster performance section
        clusters_with_metrics = [
            a
            for a in clusters
            if (a.usage_metrics or {}).get("cpu_utilization_max_24h") is not None
        ]
        if clusters_with_metrics:
            html += """
        <div class="insight-box info">
            <h3>📊 Cluster Performance (Last 24h)</h3>
            <table class="compact">
                <tr><th>Cluster</th><th>CPU Max</th><th>CPU Avg</th><th>Queries</th><th>Disk Used</th><th>Recommendation</th></tr>
            """
            for cluster in clusters_with_metrics[:10]:
                metrics = cluster.usage_metrics or {}
                cpu_max = metrics.get("cpu_utilization_max_24h", 0)
                cpu_avg = metrics.get("cpu_utilization_avg_24h", 0)
                queries = metrics.get("queries_completed_24h", 0)
                disk = metrics.get("disk_space_used_percent", 0)
                rec = metrics.get("performance_recommendation", "-")
                html += (
                    f"<tr><td>{cluster.name}</td><td>{cpu_max:.1f}%</td>"
                    f"<td>{cpu_avg:.1f}%</td><td>{queries}</td>"
                    f"<td>{disk:.1f}%</td><td>{rec if rec else '-'}</td></tr>"
                )
            html += "</table></div>"

        # Add serverless workgroup performance section
        serverless_wgs = [a for a in assets if a.asset_type == "redshift_serverless_workgroup"]
        serverless_with_metrics = [
            a for a in serverless_wgs if (a.usage_metrics or {}).get("rpu_max_7d") is not None
        ]
        if serverless_with_metrics:
            html += """
        <div class="insight-box info">
            <h3>🚀 Serverless Workgroup Utilization</h3>
            <table class="compact">
                <tr><th>Workgroup</th><th>Base RPU</th><th>Max RPU (7d)</th><th>Avg RPU (7d)</th><th>Queries (24h)</th><th>Recommendation</th></tr>
            """
            for wg in serverless_with_metrics[:10]:
                metrics = wg.usage_metrics or {}
                base = metrics.get("base_capacity", 0)
                rpu_max = metrics.get("rpu_max_7d", 0)
                rpu_avg = metrics.get("rpu_avg_7d", 0)
                queries = metrics.get("queries_completed_24h", 0) + metrics.get(
                    "queries_failed_24h", 0
                )
                rec = metrics.get("utilization_recommendation", "-")
                html += (
                    f"<tr><td>{wg.name}</td><td>{base}</td>"
                    f"<td>{rpu_max:.1f}</td><td>{rpu_avg:.1f}</td>"
                    f"<td>{queries}</td><td>{rec if rec else '-'}</td></tr>"
                )
            html += "</table></div>"

        return html
