# OSCAL Glossary

Definitions for OSCAL object types and related terms, consolidated from the [OSCAL Terminology Page](https://pages.nist.gov/OSCAL/learn/concepts/terminology/), the [NIST CSRC Glossary](https://csrc.nist.gov/glossary), and the [OSCAL Complete Schema (XSD)](https://pages.nist.gov/OSCAL/reference/).

*Consolidated: 2026-04-08*

---

## Action

An action applied by a role within a given party to the content.

Reference: [All models > metadata > actions](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/metadata/actions)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Activity

An assessment or related process that can be performed. In the [assessment plan](#assessment-plan), this is an intended activity which may be associated with an assessment [task](#task). In the [assessment results](#assessment-results), this is an activity that was actually performed as [part](#part) of an assessment.

Reference: [Assessment Plan > local-definitions > activities](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/local-definitions/activities) | [Assessment Results > local-definitions > activities](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/local-definitions/activities)

*Sources: [OSCAL Complete Schema (XSD)]; [NIST CSRC](https://csrc.nist.gov/glossary/term/activity)*

---

## Address

A postal address for a location.

Note: The NIST CSRC glossary defines "address" in cryptographic contexts (e.g., authenticated data, keying material). In OSCAL, the term refers exclusively to a physical mailing address.

Reference: [All models > metadata > locations > address](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/metadata/locations/address)

*Sources: [OSCAL Complete Schema (XSD)]; [NIST CSRC](https://csrc.nist.gov/glossary/term/address)*

---

## Assessment Assets

Identifies the assets used to perform an assessment, such as the assessment team, scanning tools, and assumptions.

Reference: [Assessment Plan > assessment-assets](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/assessment-assets) | [Assessment Results > results > local-definitions > assessment-assets](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/local-definitions/assessment-assets) | [POA&M > local-definitions > assessment-assets](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/local-definitions/assessment-assets)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Assessment Method

A local definition of a [control](#control) objective for an assessment, using [catalog](#catalog) syntax for control objectives and assessment activities. In the broader NIST context, one of three types of [actions](#action) (examine, interview, test) taken by assessors in obtaining evidence during an assessment.

Reference: [Assessment Plan > local-definitions > objectives-and-methods](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/local-definitions/objectives-and-methods) | [Assessment Results > local-definitions > objectives-and-methods](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/local-definitions/objectives-and-methods)

*Sources: [OSCAL Complete Schema (XSD)]; [NIST SP 800-53A Rev. 5](https://doi.org/10.6028/NIST.SP.800-53Ar5); [NIST CSRC](https://csrc.nist.gov/glossary/term/assessment_method)*

---

## Assessment Part

A partition of an [assessment plan](#assessment-plan) or [results](#result), or a child of another part.

Reference: [Assessment Plan > local-definitions > objectives-and-methods > parts](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/local-definitions/objectives-and-methods/parts) | [Assessment Plan > terms-and-conditions > parts](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/terms-and-conditions/parts) | [Assessment Results > local-definitions > objectives-and-methods > parts](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/local-definitions/objectives-and-methods/parts) | [Assessment Results > results > attestations > parts](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/attestations/parts)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Assessment Plan

**Also known as:** Security Assessment Plan (SAP)

The objectives for the security and privacy [control](#control) assessments and a detailed roadmap of how to conduct such assessments. The OSCAL assessment plan model represents an assessment plan such as those provided by a FedRAMP assessor.

Reference: [Assessment Plan](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan)

*Sources: [OSCAL Complete Schema (XSD)]; [NIST SP 800-53A Rev. 5](https://doi.org/10.6028/NIST.SP.800-53Ar5); [NIST CSRC](https://csrc.nist.gov/glossary/term/assessment_plan)*

---

## Assessment Results

**Also known as:** Security Assessment Results (SAR)

The [findings](#finding), [observations](#observation), [risks](#risk), and disposition produced by an assessment. The OSCAL assessment results model represents security assessment results such as those provided by a FedRAMP assessor in the FedRAMP Security Assessment Report.

Reference: [Assessment Results](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results)

*Sources: [OSCAL Complete Schema (XSD)]; [NIST SP 800-55v2](https://doi.org/10.6028/NIST.SP.800-55v2); [NIST CSRC](https://csrc.nist.gov/glossary/term/assessment_results)*

---

## Assessment Subject

**Also known as:** Subject of Assessment

Identifies system elements being assessed, such as components, [inventory items](#inventory-item), and locations. In the [assessment plan](#assessment-plan), this identifies a planned assessment subject. In the [assessment results](#assessment-results), this is an actual assessment subject and reflects any changes from the plan.

Reference: [Assessment Plan > assessment-subjects](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/assessment-subjects)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Assessment Subject Placeholder

Used when the assessment subjects will be determined as [part](#part) of one or more other assessment activities. These assessment subjects will be recorded in the [assessment results](#assessment-results) in the assessment log.

*Source: [OSCAL Complete Schema (XSD)]*

---

## Associated Risk

Relates a [finding](#finding) to a set of referenced risks that were used to determine the finding.

Reference: [Assessment Results > results > findings > related-risks](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/findings/related-risks) | [POA&M > findings > related-risks](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/findings/related-risks) | [POA&M > poam-items > related-risks](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/poam-items/related-risks)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Authorization Boundary

**Also known as:** system boundary

A description of the system's authorization boundary — all components of a system to be authorized for operation by an authorizing official, excluding separately authorized systems to which the system is connected. May be optionally supplemented by [diagrams](#diagram) that illustrate the authorization boundary.

Reference: [SSP > system-characteristics > authorization-boundary](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/system-security-plan/system-characteristics/authorization-boundary)

*Sources: [OSCAL Complete Schema (XSD)]; [NIST SP 800-37 Rev. 2](https://doi.org/10.6028/NIST.SP.800-37r2); [NIST CSRC](https://csrc.nist.gov/glossary/term/authorization_boundary)*

---

## Authorized Privilege

**Also known as:** Privilege

Identifies a specific system privilege held by a user, along with an associated description and/or rationale for the privilege.

Reference: [Assessment Plan > local-definitions > users > authorized-privileges](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/local-definitions/users/authorized-privileges) | [Assessment Results > results > local-definitions > users > authorized-privileges](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/local-definitions/users/authorized-privileges) | [SSP > system-implementation > users > authorized-privileges](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/system-security-plan/system-implementation/users/authorized-privileges)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Back Matter

A collection of resources that may be referenced from within the OSCAL document instance.

Reference: [All models > back-matter](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/back-matter)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Capability

A grouping of other components and/or capabilities. In the broader NIST context, a combination of mutually reinforcing security and/or privacy [controls](#control) implemented by technical, physical, and procedural means, typically selected to achieve a common information security- or privacy-related purpose.

Reference: [Component Definition > capabilities](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/component-definition/capabilities)

*Sources: [OSCAL Complete Schema (XSD)]; [NIST SP 800-53 Rev. 5](https://doi.org/10.6028/NIST.SP.800-53r5); [NIST CSRC](https://csrc.nist.gov/glossary/term/capability)*

---

## Catalog

A structured, organized collection of [control](#control) information. An OSCAL catalog allows control requirements to be grouped, and allows individual control requirements to contain subordinate control requirements (enhancements), control objectives, [assessment methods](#assessment-method), references, and other content. Catalogs may also define objectives and methods for assessing the controls.

Reference: [Catalog](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/catalog)

*Sources: [OSCAL Terminology Page](https://pages.nist.gov/OSCAL/learn/concepts/terminology/); [OSCAL Complete Schema (XSD)]*

---

## Characterization

A collection of descriptive data about the containing object from a specific [origin](#origin). Note: The NIST CSRC glossary defines this term in the context of clock/oscillator performance testing, which is unrelated to its OSCAL usage.

Reference: [Assessment Results > results > risks > characterizations](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/risks/characterizations) | [POA&M > risks > characterizations](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/risks/characterizations)

*Sources: [OSCAL Complete Schema (XSD)]; [NIST CSRC](https://csrc.nist.gov/glossary/term/characterization)*

---

## Component Definition

A collection of component descriptions, which may optionally be grouped by [capability](#capability).

Reference: [Component Definition](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/component-definition)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Confidence Score

A string category or a decimal value from 0–1 representing a percentage, describing an estimation of the author's confidence that a [mapping](#mapping) is correct and accurate.

Reference: [Mapping Collection > mappings > confidence-score](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/mapping-collection/mappings/confidence-score) | [Mapping Collection > mappings > maps > confidence-score](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/mapping-collection/mappings/maps/confidence-score) | [Mapping Collection > provenance > confidence-score](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/mapping-collection/provenance/confidence-score)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Control

A structured object representing a requirement or guideline, which when implemented will reduce an aspect of [risk](#risk) related to an information system and its information. More broadly, controls are policies, procedures, guidelines, practices, or organizational structures that manage security, privacy, and other risks.

Reference: [Catalog > controls](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/catalog/controls) | [Catalog > controls > controls](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/catalog/controls/controls) | [Catalog > groups > controls](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/catalog/groups/controls) | [Catalog > groups > controls > controls](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/catalog/groups/controls/controls)

*Sources: [OSCAL Complete Schema (XSD)]; [NIST SP 800-63-4](https://doi.org/10.6028/NIST.SP.800-63-4); [NIST CSRC](https://csrc.nist.gov/glossary/term/controls)*

---

## Control Implementation

Describes how the containing component or [capability](#capability) implements an individual control (in a [component definition](#component-definition)), or how the system satisfies a set of controls (in a [system security plan](#system-security-plan)).

Reference: [Component Definition > capabilities > control-implementations](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/component-definition/capabilities/control-implementations) | [Component Definition > components > control-implementations](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/component-definition/components/control-implementations) | [SSP > control-implementation](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/system-security-plan/control-implementation)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Coverage

A decimal value from 0–1 representing the percentage coverage of the targets by the sources in a [mapping](#mapping). In the broader NIST assessment context, an attribute of an [assessment method](#assessment-method) that addresses the scope or breadth of the assessment objects included in the assessment.

Reference: [Mapping Collection > mappings > coverage](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/mapping-collection/mappings/coverage) | [Mapping Collection > mappings > maps > coverage](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/mapping-collection/mappings/maps/coverage) | [Mapping Collection > provenance > coverage](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/mapping-collection/provenance/coverage)

*Sources: [OSCAL Complete Schema (XSD)]; [NIST SP 800-53A Rev. 5](https://doi.org/10.6028/NIST.SP.800-53Ar5); [NIST CSRC](https://csrc.nist.gov/glossary/term/coverage)*

---

## Data Flow

A description of the logical flow of information within the system and across its boundaries, optionally supplemented by [diagrams](#diagram) that illustrate these flows.

Reference: [SSP > system-characteristics > data-flow](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/system-security-plan/system-characteristics/data-flow)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Defined Component

**Also known as:** Component

A defined component that can be [part](#part) of an implemented system.

Reference: [Component Definition > components](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/component-definition/components)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Diagram

A graphic that provides a visual representation of the system, or some aspect of it.

Reference: [SSP > system-characteristics > authorization-boundary > diagrams](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/system-security-plan/system-characteristics/authorization-boundary/diagrams) | [SSP > system-characteristics > data-flow > diagrams](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/system-security-plan/system-characteristics/data-flow/diagrams) | [SSP > system-characteristics > network-architecture > diagrams](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/system-security-plan/system-characteristics/network-architecture/diagrams)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Document Id

**Also known as:** Document Identifier

A document identifier qualified by an identifier scheme.

Reference: [All models > back-matter > resources > document-ids](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/back-matter/resources/document-ids) | [All models > metadata > document-ids](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/metadata/document-ids)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Finding

Describes an individual finding produced during an assessment.

Reference: [Assessment Results > results > findings](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/findings) | [POA&M > findings](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/findings)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Finding Target

**Also known as:** Objective Status

Captures an assessor's conclusions regarding the degree to which an objective is satisfied.

Reference: [Assessment Results > results > findings > target](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/findings/target) | [POA&M > findings > target](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/findings/target)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Gap Summary

A by-id collection of all [controls](#control) that were not mapped in a [mapping collection](#mapping-collection). If a control is partially mapped, the unmappable [parts](#part) should be documented in the relationship qualifier.

Reference: [Mapping Collection > mappings > source-gap-summary](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/mapping-collection/mappings/source-gap-summary) | [Mapping Collection > mappings > target-gap-summary](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/mapping-collection/mappings/target-gap-summary)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Group

**Also known as:** Control Group

A group of [controls](#control), or of groups of controls. Groups provide organizational structure within a [catalog](#catalog) or [profile](#profile).

Reference: [Catalog > groups](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/catalog/groups) | [Catalog > groups > groups](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/catalog/groups/groups) | [Profile > merge > custom > groups](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/profile/merge/custom/groups) | [Profile > merge > custom > groups > groups](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/profile/merge/custom/groups/groups)

*Sources: [OSCAL Complete Schema (XSD)]; [NIST CSRC](https://csrc.nist.gov/glossary/term/group)*

---

## Impact

**Also known as:** Impact Level

The expected level of impact resulting from the described information.

Reference: [SSP > system-characteristics > system-information > information-types > availability-impact](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/system-security-plan/system-characteristics/system-information/information-types/availability-impact) | [SSP > system-characteristics > system-information > information-types > confidentiality-impact](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/system-security-plan/system-characteristics/system-information/information-types/confidentiality-impact) | [SSP > system-characteristics > system-information > information-types > integrity-impact](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/system-security-plan/system-characteristics/system-information/information-types/integrity-impact)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Implementation Status

Indicates the degree to which a given [control](#control) is implemented.

Reference: [Assessment Results > results > findings > target > implementation-status](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/findings/target/implementation-status) | [POA&M > findings > target > implementation-status](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/findings/target/implementation-status) | [SSP > control-implementation > implemented-requirements > by-components > implementation-status](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/system-security-plan/control-implementation/implemented-requirements/by-components/implementation-status)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Implemented Requirement

**Also known as:** Control-based Requirement

Describes how the containing component or [capability](#capability) implements an individual [control](#control) (in a [component definition](#component-definition)), or how the system satisfies the requirements of an individual control (in a [system security plan](#system-security-plan)).

Reference: [Component Definition > capabilities > control-implementations > implemented-requirements](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/component-definition/capabilities/control-implementations/implemented-requirements) | [Component Definition > components > control-implementations > implemented-requirements](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/component-definition/components/control-implementations/implemented-requirements) | [SSP > control-implementation > implemented-requirements](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/system-security-plan/control-implementation/implemented-requirements)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Incorporates Component

The collection of components comprising a [capability](#capability).

Reference: [Component Definition > capabilities > incorporates-components](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/component-definition/capabilities/incorporates-components)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Inventory Item

A single managed inventory item within the system.

Reference: [Assessment Plan > local-definitions > inventory-items](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/local-definitions/inventory-items) | [Assessment Results > results > local-definitions > inventory-items](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/local-definitions/inventory-items) | [POA&M > local-definitions > inventory-items](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/local-definitions/inventory-items) | [SSP > system-implementation > inventory-items](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/system-security-plan/system-implementation/inventory-items)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Local Definitions

Data objects used in the [assessment plan](#assessment-plan) or POA&M that do not appear in the referenced SSP. In a POA&M, allows components and [inventory items](#inventory-item) to be defined when no OSCAL-based SSP exists or is not delivered with the POA&M.

Reference: [Assessment Plan > local-definitions](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/local-definitions) | [Assessment Results > local-definitions](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/local-definitions) | [Assessment Results > results > local-definitions](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/local-definitions) | [POA&M > local-definitions](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/local-definitions)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Local Objective

**Also known as:** Assessment-Specific Control Objective

A local definition of a [control](#control) objective for an assessment, using [catalog](#catalog) syntax for control objectives and assessment [actions](#action).

Reference: [Assessment Plan > local-definitions > objectives-and-methods](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/local-definitions/objectives-and-methods) | [Assessment Results > local-definitions > objectives-and-methods](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/local-definitions/objectives-and-methods)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Logged By

Indicates who created a log entry and in what role.

Reference: [Assessment Results > results > assessment-log > entries > logged-by](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/assessment-log/entries/logged-by) | [POA&M > risks > risk-log > entries > logged-by](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/risks/risk-log/entries/logged-by)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Map

**Also known as:** Mapping Entry

A relationship-based [mapping](#mapping) between a source and target set consisting of members (i.e., [controls](#control), control [statements](#statement)) from the respective source and target.

Reference: [Mapping Collection > mappings > maps](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/mapping-collection/mappings/maps)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Mapping

**Also known as:** concept mapping

An indication that one concept is related to another concept. A mapping describes the context and intended use of a mapping set between [control](#control) frameworks.

Reference: [Mapping Collection > mappings](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/mapping-collection/mappings)

*Sources: [OSCAL Complete Schema (XSD)]; [NIST IR 8477](https://doi.org/10.6028/NIST.IR.8477); [NIST CSRC](https://csrc.nist.gov/glossary/term/mapping)*

---

## Mapping Collection

A collection of relationship-based [control](#control) and/or control [statement](#statement) mappings.

Reference: [Mapping Collection](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/mapping-collection)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Mapping Item

**Also known as:** Mapping Entry Item

A specific edge within a source or target that is the subject of a mapping.

Reference: [Mapping Collection > mappings > maps > sources](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/mapping-collection/mappings/maps/sources) | [Mapping Collection > mappings > maps > targets](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/mapping-collection/mappings/maps/targets)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Mapping Provenance

Describes requirements, incompatibilities, and gaps identified between a target and source in a [mapping item](#mapping-item).

Reference: [Mapping Collection > provenance](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/mapping-collection/provenance)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Mapping Resource Reference

**Also known as:** Mapped Resource Reference

A reference to a resource that is either the source or the target of a mapping.

Reference: [Mapping Collection > mappings > source-resource](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/mapping-collection/mappings/source-resource) | [Mapping Collection > mappings > target-resource](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/mapping-collection/mappings/target-resource)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Matching

The method used for relating [controls](#control) within a [mapping](#mapping). The supported methods are aligned with NIST IR 8477, Section 4.3 Set Theory Relationship Mapping.

Reference: [Mapping Collection > mappings > source-gap-summary > unmapped-controls > matching](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/mapping-collection/mappings/source-gap-summary/unmapped-controls/matching) | [Mapping Collection > mappings > target-gap-summary > unmapped-controls > matching](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/mapping-collection/mappings/target-gap-summary/unmapped-controls/matching) | [Profile > imports > exclude-controls > matching](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/profile/imports/exclude-controls/matching) | [Profile > imports > include-controls > matching](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/profile/imports/include-controls/matching)

*Sources: [OSCAL Complete Schema (XSD)]; [NIST CSRC](https://csrc.nist.gov/glossary/term/matching)*

---

## Network Architecture

A description of the system's network architecture, optionally supplemented by [diagrams](#diagram) that illustrate the network architecture.

Reference: [SSP > system-characteristics > network-architecture](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/system-security-plan/system-characteristics/network-architecture)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Observation

Describes an individual observation made during an assessment.

Reference: [Assessment Results > results > observations](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/observations) | [POA&M > observations](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/observations)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Origin

Identifies the source of a [finding](#finding), such as a tool, interviewed person, or [activity](#activity).

Reference: [Assessment Results > results > findings > origins](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/findings/origins) | [Assessment Results > results > observations > origins](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/observations/origins) | [Assessment Results > results > risks > origins](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/risks/origins) | [Assessment Results > results > risks > remediations > origins](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/risks/remediations/origins) | [POA&M > findings > origins](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/findings/origins) | [POA&M > observations > origins](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/observations/origins) | [POA&M > poam-items > origins](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/poam-items/origins) | [POA&M > risks > origins](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/risks/origins)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Origin Actor

**Also known as:** Originating Actor

The actor that produces an [observation](#observation), a [finding](#finding), or a [risk](#risk). One or more actor types can be used to specify a person that is using a tool.

Reference: [Assessment Results > results > observations > origins > actors](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/observations/origins/actors) | [POA&M > observations > origins > actors](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/observations/origins/actors)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Parameter

Parameters provide a mechanism for the dynamic assignment of value(s) in a [control](#control). More broadly, a value used to control the operation of a function or used by a function to compute outputs.

Reference: [Catalog > controls > params](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/catalog/controls/params) | [Catalog > groups > controls > params](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/catalog/groups/controls/params) | [Catalog > groups > params](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/catalog/groups/params) | [Catalog > params](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/catalog/params) | [Profile > merge > custom > groups > params](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/profile/merge/custom/groups/params) | [Profile > modify > alters > adds > params](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/profile/modify/alters/adds/params)

*Sources: [OSCAL Complete Schema (XSD)]; [NIST CSRC](https://csrc.nist.gov/glossary/term/parameter)*

---

## Parameter Constraint

**Also known as:** Constraint

A formal or informal expression of a constraint or test applied to a parameter.

Reference: [Catalog > controls > params > constraints](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/catalog/controls/params/constraints) | [Catalog > groups > controls > params > constraints](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/catalog/groups/controls/params/constraints) | [Catalog > groups > params > constraints](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/catalog/groups/params/constraints) | [Catalog > params > constraints](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/catalog/params/constraints) | [Profile > modify > set-parameters > constraints](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/profile/modify/set-parameters/constraints)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Parameter Guideline

**Also known as:** Guideline

A prose [statement](#statement) that provides a recommendation for the use of a parameter.

Reference: [Catalog > controls > params > guidelines](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/catalog/controls/params/guidelines) | [Catalog > groups > controls > params > guidelines](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/catalog/groups/controls/params/guidelines) | [Catalog > groups > params > guidelines](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/catalog/groups/params/guidelines) | [Catalog > params > guidelines](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/catalog/params/guidelines) | [Profile > modify > set-parameters > guidelines](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/profile/modify/set-parameters/guidelines)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Parameter Selection

**Also known as:** Selection

Presents a choice among alternatives for a parameter value.

Reference: [Catalog > controls > params > select](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/catalog/controls/params/select) | [Catalog > groups > controls > params > select](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/catalog/groups/controls/params/select) | [Catalog > groups > params > select](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/catalog/groups/params/select) | [Catalog > params > select](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/catalog/params/select) | [Profile > modify > set-parameters > select](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/profile/modify/set-parameters/select)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Part

An annotated, markup-based textual element of a [control](#control)'s or [catalog](#catalog) [group](#group)'s definition, or a child of another part.

Reference: [Catalog > controls > parts](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/catalog/controls/parts) | [Catalog > groups > parts](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/catalog/groups/parts) | [Profile > merge > custom > groups > parts](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/profile/merge/custom/groups/parts) | [Profile > modify > alters > adds > parts](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/profile/modify/alters/adds/parts)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Plan Of Action And Milestones

**Also known as:** POA&M

A document that identifies [tasks](#task) needing to be accomplished, detailing resources required, milestones, and scheduled completion dates. The POA&M identifies initial and residual [risks](#risk), deviations, and disposition, such as those required by FedRAMP.

Reference: [POA&M](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones)

*Sources: [OSCAL Complete Schema (XSD)]; [NIST SP 800-53 Rev. 5](https://doi.org/10.6028/NIST.SP.800-53r5); [NIST CSRC](https://csrc.nist.gov/glossary/term/plan_of_action_and_milestones)*

---

## POA&M Item

Describes an individual POA&M item.

Reference: [POA&M > poam-items](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/poam-items)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Port Range

Where applicable, the transport layer [protocol](#protocol) port range an IPv4-based or IPv6-based service uses.

Reference: [Assessment Plan > assessment-assets > components > protocols > port-ranges](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/assessment-assets/components/protocols/port-ranges) | [Assessment Plan > local-definitions > components > protocols > port-ranges](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/local-definitions/components/protocols/port-ranges) | [Component Definition > components > protocols > port-ranges](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/component-definition/components/protocols/port-ranges) | [POA&M > local-definitions > components > protocols > port-ranges](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/local-definitions/components/protocols/port-ranges) | [SSP > system-implementation > components > protocols > port-ranges](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/system-security-plan/system-implementation/components/protocols/port-ranges)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Profile

Each OSCAL profile is defined by a profile element. A profile selects and tailors [controls](#control) from one or more [catalogs](#catalog) for a specific use case or baseline.

Reference: [Profile](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/profile)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Protocol

**Also known as:** Service Protocol Information

Information about the protocol used to provide a service.

Reference: [Assessment Plan > assessment-assets > components > protocols](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/assessment-assets/components/protocols) | [Assessment Plan > local-definitions > components > protocols](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/local-definitions/components/protocols) | [Assessment Results > results > local-definitions > components > protocols](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/local-definitions/components/protocols) | [Component Definition > components > protocols](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/component-definition/components/protocols) | [POA&M > local-definitions > assessment-assets > components > protocols](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/local-definitions/assessment-assets/components/protocols) | [POA&M > local-definitions > components > protocols](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/local-definitions/components/protocols) | [SSP > system-implementation > components > protocols](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/system-security-plan/system-implementation/components/protocols)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Qualifier Item

**Also known as:** Relationship Qualifier

Describes requirements, incompatibilities, and gaps identified between a target and source in a [mapping item](#mapping-item).

Reference: [Mapping Collection > mappings > maps > qualifiers](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/mapping-collection/mappings/maps/qualifiers)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Response

**Also known as:** Risk Response

Describes either a recommended or an actual plan for addressing a [risk](#risk).

Reference: [Assessment Results > results > risks > remediations](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/risks/remediations) | [POA&M > risks > remediations](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/risks/remediations)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Responsible Party

A reference to a set of persons and/or organizations that have responsibility for performing the referenced role in the context of the containing object.

Reference: [All models > metadata > actions > responsible-parties](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/metadata/actions/responsible-parties) | [All models > metadata > responsible-parties](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/metadata/responsible-parties) | [Assessment Plan > assessment-assets > assessment-platforms > uses-components > responsible-parties](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/assessment-assets/assessment-platforms/uses-components/responsible-parties) | [Assessment Plan > local-definitions > inventory-items > implemented-components > responsible-parties](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/local-definitions/inventory-items/implemented-components/responsible-parties) | [Assessment Plan > local-definitions > inventory-items > responsible-parties](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/local-definitions/inventory-items/responsible-parties) | [Assessment Results > results > attestations > responsible-parties](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/attestations/responsible-parties) | [Assessment Results > results > local-definitions > inventory-items > responsible-parties](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/local-definitions/inventory-items/responsible-parties) | [Mapping Collection > provenance > responsible-parties](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/mapping-collection/provenance/responsible-parties)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Responsible Role

A reference to a role with responsibility for performing a function relative to the containing object, optionally associated with a set of persons and/or organizations that perform that role.

Reference: [Assessment Plan > assessment-assets > components > responsible-roles](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/assessment-assets/components/responsible-roles) | [Assessment Plan > local-definitions > activities > responsible-roles](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/local-definitions/activities/responsible-roles) | [Assessment Plan > local-definitions > activities > steps > responsible-roles](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/local-definitions/activities/steps/responsible-roles) | [Assessment Plan > local-definitions > components > responsible-roles](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/local-definitions/components/responsible-roles) | [Assessment Plan > tasks > associated-activities > responsible-roles](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/tasks/associated-activities/responsible-roles) | [Assessment Plan > tasks > responsible-roles](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/tasks/responsible-roles) | [Assessment Results > local-definitions > activities > responsible-roles](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/local-definitions/activities/responsible-roles) | [Assessment Results > local-definitions > activities > steps > responsible-roles](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/local-definitions/activities/steps/responsible-roles)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Result

**Also known as:** Assessment Result

Used by the [assessment results](#assessment-results) and POA&M. In the assessment results, this identifies all of the assessment [observations](#observation) and [findings](#finding), initial and residual [risks](#risk), deviations, and disposition. In the POA&M, this identifies initial and residual risks, deviations, and disposition.

Reference: [Assessment Results > results](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Reviewed Controls

**Also known as:** Reviewed Controls and Control Objectives

Identifies the controls being assessed and their control objectives.

Reference: [Assessment Plan > local-definitions > activities > steps > reviewed-controls](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/local-definitions/activities/steps/reviewed-controls) | [Assessment Plan > reviewed-controls](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/reviewed-controls) | [Assessment Results > local-definitions > activities > steps > reviewed-controls](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/local-definitions/activities/steps/reviewed-controls) | [Assessment Results > results > reviewed-controls](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/reviewed-controls)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Risk

**Also known as:** Identified Risk

An identified risk within the system being assessed.

Reference: [Assessment Results > results > risks](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/risks) | [POA&M > risks](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/risks)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Security Impact Level

The overall level of expected impact resulting from unauthorized disclosure, modification, or loss of access to information.

Reference: [SSP > system-characteristics > security-impact-level](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/system-security-plan/system-characteristics/security-impact-level)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Select Control By Id

**Also known as:** Select Control

Used to select a control for inclusion/exclusion based on one or more control identifiers. A set of [statement](#statement) identifiers can be used to target the inclusion/exclusion to only specific control statements, providing more granularity over the specific statements that are within the assessment scope.

*Source: [OSCAL Complete Schema (XSD)]*

---

## Select Objective By Id

**Also known as:** Select Objective

Used to select a [control](#control) objective for inclusion/exclusion based on the control objective's identifier.

*Source: [OSCAL Complete Schema (XSD)]*

---

## Select Subject By Id

**Also known as:** Select Assessment Subject

Identifies a set of [assessment subjects](#assessment-subject) to include/exclude by UUID.

Reference: [Assessment Plan > assessment-subjects > exclude-subjects](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/assessment-subjects/exclude-subjects) | [Assessment Plan > tasks > associated-activities > subjects > exclude-subjects](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/tasks/associated-activities/subjects/exclude-subjects) | [Assessment Plan > tasks > subjects > exclude-subjects](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/tasks/subjects/exclude-subjects)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Statement

**Also known as:** Specific Control Statement, Control Statement Implementation

Identifies which statements within a [control](#control) are addressed.

Reference: [Component Definition > capabilities > control-implementations > implemented-requirements > statements](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/component-definition/capabilities/control-implementations/implemented-requirements/statements) | [Component Definition > components > control-implementations > implemented-requirements > statements](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/component-definition/components/control-implementations/implemented-requirements/statements) | [SSP > control-implementation > implemented-requirements > statements](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/system-security-plan/control-implementation/implemented-requirements/statements)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Status

Describes the operational status of the system or a [system component](#system-component).

Reference: [Assessment Plan > assessment-assets > components > status](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/assessment-assets/components/status) | [Assessment Plan > local-definitions > components > status](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/local-definitions/components/status) | [Assessment Results > results > findings > target > status](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/findings/target/status) | [Assessment Results > results > local-definitions > components > status](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/local-definitions/components/status) | [Assessment Results > results > risks > status](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/risks/status) | [Mapping Collection > mappings > status](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/mapping-collection/mappings/status) | [Mapping Collection > provenance > status](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/mapping-collection/provenance/status) | [POA&M > findings > target > status](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/findings/target/status)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Subject Reference

**Also known as:** Identifies the Subject

A human-oriented identifier reference to a resource. Use type to indicate whether the identified resource is a component, [inventory item](#inventory-item), location, user, or something else.

Reference: [Assessment Plan > tasks > subjects](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/tasks/subjects) | [Assessment Results > results > observations > subjects](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/observations/subjects)

*Source: [OSCAL Complete Schema (XSD)]*

---

## System Characteristics

Contains the characteristics of the system, such as its name, purpose, and [security impact level](#security-impact-level).

Reference: [SSP > system-characteristics](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/system-security-plan/system-characteristics)

*Source: [OSCAL Complete Schema (XSD)]*

---

## System Component

**Also known as:** component

A discrete identifiable information technology asset (hardware, software, firmware) that represents a building block of a system and can be [part](#part) of an implemented system.

Reference: [Assessment Plan > assessment-assets > components](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/assessment-assets/components) | [Assessment Plan > local-definitions > components](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/local-definitions/components) | [SSP > system-implementation > components](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/system-security-plan/system-implementation/components)

*Sources: [OSCAL Complete Schema (XSD)]; [NIST SP 800-53 Rev. 5](https://doi.org/10.6028/NIST.SP.800-53r5); [NIST CSRC](https://csrc.nist.gov/glossary/term/system_component)*

---

## System Id

**Also known as:** System Identification

A human-oriented, globally unique identifier with cross-instance scope that can be used to reference a system identification property elsewhere in this or other OSCAL instances.

Reference: [POA&M > system-id](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/system-id) | [SSP > system-characteristics > system-ids](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/system-security-plan/system-characteristics/system-ids)

*Source: [OSCAL Complete Schema (XSD)]*

---

## System Implementation

Provides information as to how the system is implemented.

Reference: [SSP > system-implementation](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/system-security-plan/system-implementation)

*Source: [OSCAL Complete Schema (XSD)]*

---

## System Information

Contains details about all information types that are stored, processed, or transmitted by the system, such as privacy information and those defined in NIST SP 800-60.

Reference: [SSP > system-characteristics > system-information](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/system-security-plan/system-characteristics/system-information)

*Source: [OSCAL Complete Schema (XSD)]*

---

## System Security Plan

**Also known as:** SSP

A document that describes how an organization meets or plans to meet the security requirements for a system, including the system boundary, the operating environment, how security requirements are implemented, and the relationships with or connections to other systems. The OSCAL SSP model represents a system security plan such as those described in NIST SP 800-18.

Reference: [SSP](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/system-security-plan)

*Sources: [OSCAL Complete Schema (XSD)]; [NIST SP 800-37 Rev. 2](https://doi.org/10.6028/NIST.SP.800-37r2); [NIST CSRC](https://csrc.nist.gov/glossary/term/system_security_plan)*

---

## System User

A type of user that interacts with the system based on an associated role. More broadly, an individual or system process acting on behalf of an individual that is authorized to access a system.

Reference: [Assessment Plan > local-definitions > users](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/local-definitions/users) | [Assessment Results > results > local-definitions > users](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/local-definitions/users) | [SSP > system-implementation > users](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/system-security-plan/system-implementation/users)

*Sources: [OSCAL Complete Schema (XSD)]; [NIST SP 800-171r3](https://doi.org/10.6028/NIST.SP.800-171r3); [NIST CSRC](https://csrc.nist.gov/glossary/term/systemuser)*

---

## Task

A scheduled event or milestone which may be associated with a series of assessment [actions](#action). More broadly, a required, recommended, or permissible action intended to contribute to the achievement of one or more outcomes of a process.

Reference: [Assessment Plan > tasks](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/tasks) | [Assessment Plan > tasks > tasks](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/tasks/tasks) | [Assessment Results > results > local-definitions > tasks](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/local-definitions/tasks) | [Assessment Results > results > local-definitions > tasks > tasks](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/local-definitions/tasks/tasks) | [Assessment Results > results > risks > remediations > tasks](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/risks/remediations/tasks) | [POA&M > risks > remediations > tasks](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/risks/remediations/tasks) | [POA&M > risks > remediations > tasks > tasks](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/risks/remediations/tasks/tasks)

*Sources: [OSCAL Complete Schema (XSD)]; [NIST SP 800-160v1r1](https://doi.org/10.6028/NIST.SP.800-160v1r1); [NIST CSRC](https://csrc.nist.gov/glossary/term/task)*

---

## Telephone Number

A telephone service number as defined by ITU-T E.164.

Reference: [All models > metadata > locations > telephone-numbers](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/metadata/locations/telephone-numbers) | [All models > metadata > parties > telephone-numbers](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-plan/metadata/parties/telephone-numbers)

*Source: [OSCAL Complete Schema (XSD)]*

---

## Threat Id

**Also known as:** Threat ID

A pointer, by ID, to an externally-defined threat.

Reference: [Assessment Results > results > risks > threat-ids](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/assessment-results/results/risks/threat-ids) | [POA&M > risks > threat-ids](https://pages.nist.gov/OSCAL-Reference/models/v1.2.1/complete/json-reference/#/plan-of-action-and-milestones/risks/threat-ids)

*Source: [OSCAL Complete Schema (XSD)]*
