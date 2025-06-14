from sigma.pipelines.common import logsource_windows, windows_logsource_mapping
from sigma.pipelines.base import Pipeline
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

# TODO: the following code is just an example extend/adapt as required.
# See https://sigmahq-pysigma.readthedocs.io/en/latest/Processing_Pipelines.html for further documentation.

@Pipeline
def SecurityOnion_pipeline() -> ProcessingPipeline:        # Processing pipelines should be defined as functions that return a ProcessingPipeline object.
    return ProcessingPipeline(
        name="OQL example pipeline",
        allowed_backends=frozenset(),                                               # Set of identifiers of backends (from the backends mapping) that are allowed to use this processing pipeline. This can be used by frontends like Sigma CLI to warn the user about inappropriate usage.
        priority=20,            # The priority defines the order pipelines are applied. See documentation for common values.
        items=[
            ProcessingItem(     # This is an example for processing items generated from the mapping above.
                identifier=f"SecurityOnion_windows_{service}",
                transformation=AddConditionTransformation({ "source": source}),
                rule_conditions=[logsource_windows(service)],
            )
            for service, source in windows_logsource_mapping.items()
        ] + [
            ProcessingItem(     # Field mappings
                identifier="SecurityOnion_field_mapping",
                transformation=FieldMappingTransformation({
                    "EventID": "event_id",      # TODO: define your own field mappings
                })
            )
        ],
    )