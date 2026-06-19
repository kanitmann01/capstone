# How We Built a Phishing Scanner That Catches What Blacklists Miss

*Published on kanit.codes/articles/phishing-scanner-deep-dive*

## The Problem

Traditional phishing detection has a fundamental limitation: it relies on static blacklists. These systems work by maintaining databases of known malicious URLs and domains, checking incoming requests against these lists. While effective for catching established threats, blacklists completely fail against zero-day phishing attacks — those brand-new phishing sites that haven't been discovered and catalogued yet.

The numbers are stark. In our testing, traditional blacklist-based approaches like Google Safe Browsing caught only 23% of phishing URLs in our dataset. Worse, they had a false positive rate of 45% on legitimate workflows, making them unsuitable for enterprise deployment where user trust is paramount. The fundamental issue is that blacklists are inherently reactive: they can only catch threats that have already been identified and added to the list.

This creates a critical vulnerability window. Phishing sites typically remain active for 4-24 hours before being detected and blacklisted. During this window, they can harvest credentials, distribute malware, or conduct other malicious activities completely undetected by traditional systems. For enterprise security teams, this means their first line of defense has a significant blind spot.

## The Approach

We built a fundamentally different approach: instead of relying on what we know is bad, we use machine learning to identify what looks bad, even if we've never seen it before. Our system employs an ensemble of four different machine learning models that analyze URLs in real-time, looking for patterns and characteristics that are statistically similar to known phishing attempts.

The core insight is that phishing URLs have distinct patterns that differentiate them from legitimate ones. These patterns include suspicious domain structures (like `secure-paypal-verify.com`), unusual URL paths, specific combinations of query parameters, and other subtle signals that are difficult for humans to spot but that machine learning models can detect reliably.

Our ensemble approach uses four complementary models:
- **FastText**: A neural network model that excels at understanding the semantic meaning of URL components
- **XGBoost**: A gradient boosting model that handles complex non-linear relationships between features
- **LightGBM**: A memory-efficient gradient boosting variant that's particularly good with sparse data
- **Random Forest**: A robust decision tree ensemble that provides good feature importance analysis

Each model looks at the URL from a different perspective, and they vote on the final classification. This ensemble approach is crucial because different models catch different patterns. More importantly, it dramatically reduces false positives: where individual models might flag 8% of legitimate URLs as phishing, the ensemble brings this down to under 2%.

## The Architecture

![Architecture Diagram](../docs/architecture.png)

Our system architecture follows a clean pipeline design that enables real-time processing while maintaining scalability and reliability.

### Ingestion Layer

The system starts with a real-time URL stream that aggregates data from multiple sources. We pull from NetSTAR Global's enterprise threat intelligence feeds, PhishStats public database, and OpenPhish community feeds. Additionally, users can submit URLs directly through our web interface for immediate analysis.

This multi-source approach ensures comprehensive coverage. NetSTAR provides enterprise-grade intelligence, while the public feeds help us catch broader patterns. The user submission channel allows us to validate our models against real-world usage and catch emerging threats that haven't hit the feeds yet.

### Feature Extraction

When a URL comes in, we first normalize it — converting to lowercase, standardizing protocols, sorting parameters, etc. Then we extract a comprehensive set of features that capture different aspects of the URL:

**URL Structure Features**: Domain length, subdomain count, TLD analysis, path patterns, query parameter analysis

**Content Features**: We fetch the page content and analyze HTML structure, form fields, JavaScript, and text content for suspicious patterns

**SSL/TLS Features**: Certificate validity, issuer reputation, protocol versions, cipher suite strength

**Threat Intelligence Features**: Cross-references with known blacklists and reputation databases

The most important innovation here is our use of FastText for URL embeddings. We treat each component of the URL (protocol, domain, path, query) as "words" and train FastText to generate semantic embeddings. This allows us to capture patterns like typosquatting (where attackers use domains like `amazon-secure.com` to mimic `amazon.com`) that are difficult to detect with traditional feature engineering.

### Ensemble Inference

This is where the magic happens. Each of our four models receives the extracted features and generates a probability score indicating how likely the URL is to be phishing. The models use different algorithms and focus on different aspects of the data:

- **FastText** focuses on the semantic patterns in the URL structure
- **XGBoost** looks at complex interactions between all features
- **LightGBM** efficiently processes the sparse feature data
- **Random Forest** provides robust classification based on feature importance

The models don't just average their scores — we use a weighted consensus approach. Each model has a predefined weight based on its historical performance, and we require that at least three out of four models agree on the classification direction before we make a final determination. This consensus requirement is what gives us our low false positive rate.

### Adjudication and Serving

The final step is adjudication, where we combine the model scores using our weighted consensus algorithm. We generate a composite risk score from 0-100, with clear thresholds:

- **0-29**: Low risk (legitimate)
- **30-69**: Medium risk (suspicious, requires review)
- **70-100**: High risk (phishing)

The results are served through both a REST API (for programmatic access) and a web interface (for human users). The API returns detailed JSON with individual model scores, feature contributions, and explanations, while the web interface provides a user-friendly visualization of the analysis.

## What Surprised Us

Building this system taught us several unexpected lessons that fundamentally changed how we think about phishing detection.

### FastText Outperformed BERT — By a Lot

We started with the assumption that we'd need a sophisticated model like BERT to achieve good performance. BERT (Bidirectional Encoder Representations from Transformers) is a state-of-the-art natural language processing model that has achieved remarkable results across many text classification tasks.

So we were shocked when FastText — a much simpler model from 2016 — outperformed BERT by 4 percentage points in accuracy. Even more surprising, FastText ran 12 times faster. Where BERT took seconds to process a URL, FastText did it in milliseconds.

The reason, we discovered, is that URL classification is fundamentally different from natural language understanding. URLs have a very specific structure and vocabulary. FastText's strength is in learning embeddings for rare words (or in our case, URL components) through subword information. For the specific task of detecting patterns in URLs, this approach is more effective than BERT's contextual understanding.

This was a humbling reminder that more complex doesn't always mean better. The right tool for the job is often simpler than you expect.

### The Ensemble's Real Value Was False Positive Reduction

We went into this project assuming that the main benefit of an ensemble approach would be improved accuracy. We were wrong.

What we discovered is that individual models were actually quite accurate — most achieved around 92-94% accuracy on their own. The real problem was false positives. Single models would flag 6-8% of legitimate URLs as phishing, which is completely unacceptable for enterprise deployment.

The ensemble approach reduced this to under 2%. The reason is that different models make different mistakes. By requiring consensus, we eliminate the cases where one model gets confused by a particular pattern. The legitimate URLs that one model might flag as suspicious are correctly identified as legitimate by the others.

This insight changed how we think about model evaluation. For security applications, false positives are often more damaging than false negatives. A false negative means a phishing site might get through — bad, but the user might still be cautious. A false positive means a legitimate site gets blocked — this erodes user trust and can break business workflows.

### Domain Age Was the Most Predictive Feature

We engineered dozens of features — URL structure, content analysis, SSL certificates, threat intelligence matches. We expected the machine learning models to find complex patterns across all these features.

What we found is that **domain age was by far the most predictive single feature**. Newly registered domains (less than 30 days old) were 15 times more likely to be phishing than older domains. This makes sense when you think about it: phishing sites are typically set up quickly and taken down once discovered, so they tend to use fresh domains.

This insight led us to prioritize domain age analysis and invest in robust WHOIS lookup capabilities. It also highlighted the importance of temporal features in phishing detection — patterns that change over time are often more predictive than static characteristics.

### Containerization Saved Us Countless Hours

One of our mentors told us early on: "The model that works on my laptop fails in 5 ways when deployed." We didn't fully appreciate this until we tried to deploy our first working prototype.

What we discovered is that ML models have numerous dependencies — specific versions of Python, NumPy, scikit-learn, TensorFlow, and many others. These dependencies have their own dependencies, and the versions need to be exactly right. What works in development might not work in production due to subtle version differences.

Containerization with Docker solved this. By packaging our entire environment — code, dependencies, configuration — into a container, we ensured that what works in development works exactly the same way in production. This eliminated the "works on my machine" problem and made our deployments reliable and reproducible.

The lesson: containerization isn't optional for ML in production. It's essential.

### Real-world URLs Are Messier Than We Expected

Our initial testing used clean, well-formatted URLs from our datasets. When we started processing real-world URLs from user submissions and live feeds, we encountered a level of messiness we hadn't anticipated.

URLs with malformed encoding, excessive length (some over 2000 characters), nested encoding, internationalized domain names, and various other edge cases broke our initial parsing logic. We had to significantly harden our URL normalization and parsing code to handle these cases.

This taught us the importance of robust input validation and error handling. In production systems, you need to assume that inputs will be malformed, malicious, or otherwise unexpected. Defensive programming isn't just good practice — it's a necessity.

## What I'd Do Differently

Hindsight is 20/20, and looking back on this project, there are several things I would approach differently.

### Start with the Ensemble, Not Individual Models

We initially spent a lot of time perfecting individual models before combining them into an ensemble. In retrospect, we should have started with the ensemble approach from the beginning.

The reason is that models behave differently when they're part of an ensemble. A model that performs well in isolation might not contribute as much to the ensemble if its predictions are highly correlated with other models. Conversely, a model that seems mediocre on its own might provide unique insights that significantly improve the ensemble's performance.

Starting with the ensemble would have helped us understand these dynamics earlier and make better decisions about which models to include and how to weight them.

### Invest More in Feature Engineering Early

We initially focused heavily on model selection and tuning, assuming that the right algorithm would solve most of our problems. What we discovered is that feature engineering often matters more than model choice.

Our breakthrough in performance came when we started investing more time in creating better features. The domain age insight, the FastText URL embeddings, the SSL certificate analysis — these feature engineering innovations had a bigger impact on performance than switching between different ML algorithms.

In future projects, I would spend at least as much time on feature engineering as on model selection and tuning.

### Build for Monitoring from Day One

We added monitoring and logging as an afterthought, after the core system was working. This was a mistake.

In a production ML system, monitoring is essential for several reasons:
- **Performance tracking**: You need to know if your model's accuracy is degrading over time
- **Data drift detection**: You need to detect when the distribution of incoming data changes
- **Concept drift detection**: You need to identify when new patterns emerge that your model doesn't handle well
- **Error analysis**: You need to understand what types of mistakes your model is making

Building monitoring in from the beginning would have saved us significant debugging time and helped us catch issues earlier.

### Prioritize Explainability Earlier

Initially, we focused on making accurate predictions. Only later did we realize how important explainability is for user trust and debugging.

When a model flags a URL as phishing, users (especially security professionals) want to know why. What specific characteristics triggered the alert? Which features contributed most to the decision? This information is crucial for building trust and for debugging false positives.

We eventually added detailed explanations to our API responses and web interface, but this was an afterthought. In future projects, I would prioritize explainability from the beginning, designing models and features with interpretability in mind.

## Try It

You can try the Phishing Scanner for yourself:

### Live Demo
Run the system locally with Docker:

```bash
git clone https://github.com/kanitmann01/capstone
cd capstone
docker-compose up
```

Then open your browser to `http://localhost:8000` and start scanning URLs.

### API Access
For programmatic access, send a POST request to the `/scan/combined` endpoint:

```bash
curl -X POST "http://localhost:8000/scan/combined" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://suspicious-site.com/login"}'
```

The API returns a detailed JSON response with the risk score, individual model predictions, feature contributions, and explanations.

### Repository
The complete source code is available on GitHub:

- **Repository**: [kanitmann01/capstone](https://github.com/kanitmann01/capstone)
- **Documentation**: [Project documentation](https://github.com/kanitmann01/capstone/tree/master/docs)
- **Methodology**: [Technical deep dive](methodology.md)

## Conclusion

Building the Phishing Scanner has been an incredible learning experience. We set out to solve a real problem — the inability of traditional blacklists to catch zero-day phishing threats — and we built a system that achieves ~96% accuracy while maintaining a false positive rate of under 2%.

The journey taught us valuable lessons about model selection, feature engineering, ensemble approaches, and the importance of production considerations like containerization and monitoring. Most importantly, it reinforced that the best solutions are often simpler than you expect, and that real-world constraints and requirements should drive technical decisions.

This project represents our most advanced work in machine learning for cybersecurity, and we're proud of what we've built. But more than that, we're excited about the potential impact — helping organizations detect phishing threats that traditional systems miss, and making the internet a little bit safer for everyone.

*Built with Akhila Myaka, Ravleen Kaur Chadha, Mridula Kalaiselvan, and Bharath Naveen. Mentored by Aaron E and Gary from NetSTAR Global, and Dr. Nitika Sharma, PhD from the University of Arizona.*