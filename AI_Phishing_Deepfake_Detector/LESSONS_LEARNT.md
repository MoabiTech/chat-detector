# Lessons Learnt

## Part I - Risk Management

### Key Lessons
- **Risk Identification**: Systematic approach to identifying assets, threats and vulnerabilities is crucial for comprehensive security coverage
- **Risk Assessment**: Quantitative and qualitative assessment using likelihood-impact matrices helps prioritize risks effectively
- **Risk Control**: Selecting appropriate controls (preventive, detective, corrective) requires balancing security, cost and usability
- **SecSDLC Integration**: Security must be integrated throughout the development lifecycle, not as an afterthought
- **Threat Landscape**: AI-generated phishing and deepfakes represent evolving threats requiring adaptive detection approaches

## Part II - AI Detector Development

### Technical Lessons
- **Explainability Matters**: Rule-based systems with transparent scoring build trust and help users understand decisions
- **Honest Limitations**: It's critical to clearly state what the system can and cannot do, especially for AI detection
- **Data Integrity**: Hashing and non-destructive processing are essential for forensics and evidence preservation
- **Performance Considerations**: CPU-only environments require efficient approaches; lazy loading and optimized models are necessary
- **Modular Design**: Separating concerns (email analysis, media inspection, reporting) makes integration of ML models easier
- **Multi-modal Detection**: Different media types require different analysis approaches and tools
- **URL Safety**: Extracting without opening is a critical security practice

### Project Management Lessons
- **Time Management**: Balancing documentation (risk management) and implementation requires careful planning
- **Testing is Essential**: Measuring actual performance vs assumptions is important for accurate reporting
- **Documentation**: Clear, detailed documentation is as important as working code for academic submissions
- **Team Collaboration**: Clear role allocation and regular communication ensure all aspects are covered

### Challenges Faced
- Understanding the full scope of requirements across both parts
- Balancing prototype functionality with academic requirements
- Ensuring honest reporting without overclaiming capabilities
- Working within hardware constraints (limited RAM, CPU-only)

### Future Improvements
- Integrate validated trained models with proper evaluation metrics
- Expand test datasets with labelled samples
- Implement more sophisticated detection techniques
- Add continuous learning capabilities
- Improve user interface and experience
