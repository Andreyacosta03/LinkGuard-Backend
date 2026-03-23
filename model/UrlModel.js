export default class UrlModel {
  static async checkUrl(url) {
    try {
      // const API_KEY = process.env.API_KEY;
      const API_KEY = process.env.API_KEY_VIRUSTOTAL;
      const urlId = Buffer.from(url).toString("base64").replace(/=/g, "");

      const response = await fetch(
        `https://www.virustotal.com/api/v3/urls/${urlId}`,
        {
          method: "GET",
          headers: {
            "x-apikey": API_KEY,
            "Content-Type": "application/json",
          },
        },
      );

      const data_response = await response.json();

      if (!response.ok) {
        return {
          error: true,
          status: response.status,
          message:
            data_response.error?.message || "Error al consultar VirusTotal",
        };
      }

      const engines = data_response.data.attributes.last_analysis_results;

      const ENGINE_WEIGHTS = {
        "Google Safebrowsing": 50,
        Kaspersky: 50,
        BitDefender: 30,
        ESET: 30,
        DEFAULT: 10,
      };

      let rawWarnings = {};
      let maxPossiblePoints = 0;
      let riskPoints = 0;

      for (const [name, value] of Object.entries(engines)) {
        if (
          value.category === "unrated" ||
          value.category === "undetected" ||
          value.category === "type-unsupported" ||
          value.category === "timeout"
        )
          continue;

        const currentWeight = ENGINE_WEIGHTS[name] || ENGINE_WEIGHTS.DEFAULT;
        maxPossiblePoints += currentWeight;

        if (value.category === "malicious" || value.category === "suspicious") {
          riskPoints +=
            value.category === "malicious" ? currentWeight : currentWeight / 2;

          const reason = value.result || "Unknown threat";
          rawWarnings[reason] = (rawWarnings[reason] || 0) + 1;
        }
      }

      const topThreats = Object.entries(rawWarnings)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map((entry) => entry[0]);

      const malicious_percentage =
        maxPossiblePoints > 0
          ? Math.round((riskPoints / maxPossiblePoints) * 100)
          : 0;

      const totalEngines = Object.keys(engines).length;
      const urlData = data_response.data.attributes.url;

      const responseData = {
        id: data_response.data.id,
        urlData,
        totalEngines,
        malicious_percentage,
        threatTypes: topThreats,
      };

      if (malicious_percentage > 60) {
        return { ...responseData, isMalicious: true };
      } else if (malicious_percentage >= 30) {
        return { ...responseData, isSuspicious: true };
      }

      return { ...responseData, isSafe: true };
    } catch (error) {
      console.error("Error checking URL:", error.message);
      return { error: true, message: error.message, status: 500 };
    }
  }
}
