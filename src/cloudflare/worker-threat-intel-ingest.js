import { Client, fql } from "fauna";

export default {
  async fetch(request, env, ctx) {
   const d1 = env.THREAT_INTEL_DB;
    const fauna = new Client({
      secret: env.FAUNA_SECRET,
    });
        const threatIntelUrls = [
          'https://example.com/threat-intel-feed1.json',
          'https://example.com/threat-intel-feed2.json',
           // Add more URLs
          ];

         let allThreatIntel = [];
       for(const url of threatIntelUrls){
           try {
              const response = await fetch(url);
              if (!response.ok) {
                console.error(`Failed to fetch threat intel from ${url}: ${response.status} ${response.statusText}`);
                 continue; // Skip to the next URL
              }
              const data = await response.json();
                allThreatIntel= [...allThreatIntel, ...data.objects]; // Assuming "objects" is the key of your stix data
           }
           catch(error){
             console.error(`Error fetching threat intel from ${url}:`, error);
           }
      }

     const stixObjects= allThreatIntel; // You should implement your fetching strategy as discussed previously.
        function filterRelevantThreatIntel(stixObjects) {
         //Implement filtering here as before
        }
       async function storeInD1(d1, data){
          for (const threat of data) {
           try {
             const searchableText = `${threat.type} ${threat.value || ''} ${threat.description || ''} ${threat.cve || ''} ${threat.name || ''} ${threat.cpe || ''}`
            await d1.prepare('INSERT INTO threat_intel (type, value, labels, description, timestamp , confidence, cve, name, cpe, modified, searchable_text) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(
                 threat.type,
                 threat.value || null,
                 JSON.stringify(threat.labels) || null,
                 threat.description || null,
                 threat.timestamp || null,
                threat.confidence || null,
                threat.cve || null,
                threat.name || null,
                threat.cpe || null,
               threat.modified || null,
                searchableText
           ).run()

           } catch (e) {
             console.error("Error D1", e, threat)
           }

         }
       }
       async function storeInFaunaDB(data, fauna) {
              for (const threat of data) {
                   try{
                      const query_create= fql`Threats.create({ data: ${threat}})`;
                      await fauna.query(query_create);

                    }
                    catch(e){
                      console.error("error fauna", e, threat)
                    }
              }
         }
       const relevantIndicators= filterRelevantThreatIntel(stixObjects);
      await storeInD1(d1, relevantIndicators);
      await storeInFaunaDB(relevantIndicators, fauna);
    console.log("Threat intel ingestion finished");
     return new Response('threat intel has been updated');
   },
};