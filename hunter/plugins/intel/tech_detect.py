"""Technology detection — identifies CMS, frameworks, languages."""
from .. import Plugin, Budget
import re


class TechDetectPlugin(Plugin):
    name = "intel.tech_detect"
    description = "Technology/CMS detection for targeted scanning"
    category = "intel"

    CMS_PATTERNS = {
        "wordpress": ["/wp-content/", "/wp-includes/", "/wp-admin/", "wordpress"],
        "joomla": ["/components/", "/modules/", "/templates/", "joomla"],
        "drupal": ["/sites/default/", "/misc/drupal.js", "drupal", "x-drupal"],
        "shopify": ["cdn.shopify.com", "shopify"],
        "wix": ["wix.com", "wixstatic.com"],
        "squarespace": ["squarespace.com", "squarespace-cdn"],
        "magento": ["/skin/frontend/", "magento", "mage/cookies"],
    }

    FRAMEWORK_PATTERNS = {
        "react": ["react", "_next/static", "__NEXT_DATA__"],
        "angular": ["ng-version", "angular"],
        "vue": ["vue.js", "__vue__", "nuxt"],
        "django": ["csrfmiddlewaretoken", "django"],
        "flask": ["werkzeug", "flask"],
        "laravel": ["laravel", "x-powered-by: laravel"],
        "spring": ["spring", "whitelabel error"],
        "express": ["x-powered-by: express"],
        "rails": ["x-powered-by: phusion", "rails"],
        "asp.net": ["x-aspnet", "asp.net", "__viewstate"],
    }

    def run(self, budget: Budget):
        live_urls = self.state.get_state("recon.http_probe", "live_urls", [])
        tech_stack = self.state.get_state("recon.http_probe", "tech_stack", {})

        if not live_urls:
            return self.state

        detected_cms = None
        detected_frameworks = []

        # Check tech stack from httpx
        tech_str = " ".join(tech_stack.keys()).lower()

        for cms, patterns in self.CMS_PATTERNS.items():
            if any(p in tech_str for p in patterns):
                detected_cms = cms
                break

        for fw, patterns in self.FRAMEWORK_PATTERNS.items():
            if any(p in tech_str for p in patterns):
                detected_frameworks.append(fw)

        # If no CMS detected from httpx, probe a few URLs directly
        if not detected_cms:
            for url in live_urls[:5]:
                out = self.run_tool(["curl", "-sL", "--max-time", "5", url], timeout=10)
                if not out:
                    continue
                out_lower = out.lower()
                for cms, patterns in self.CMS_PATTERNS.items():
                    if any(p in out_lower for p in patterns):
                        detected_cms = cms
                        break
                if detected_cms:
                    break

        self.state.set_state(self.name, "cms", detected_cms)
        self.state.set_state(self.name, "frameworks", detected_frameworks)
        
        if detected_cms:
            self.log(f"CMS detected: {detected_cms}")
        if detected_frameworks:
            self.log(f"Frameworks: {', '.join(detected_frameworks)}")
        if not detected_cms and not detected_frameworks:
            self.log("No CMS/framework detected")
        
        return self.state
