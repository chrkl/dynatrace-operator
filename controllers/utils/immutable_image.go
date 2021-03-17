package utils

import (
	dynatracev1alpha1 "github.com/Dynatrace/dynatrace-operator/api/v1alpha1"
)

// SetUseImmutableImageStatus updates the status' UseImmutableImage field to indicate whether the Operator should use
// immutable images or not.
func SetUseImmutableImageStatus(instance *dynatracev1alpha1.DynaKube, fs *dynatracev1alpha1.FullStackSpec) bool {
	if fs.UseImmutableImage == instance.Status.OneAgent.UseImmutableImage {
		return false
	}

	instance.Status.OneAgent.UseImmutableImage = fs.UseImmutableImage
	return true
}
