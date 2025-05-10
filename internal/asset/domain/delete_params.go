package domain

// DeleteParams encapsulates all possible parameters for asset deletion operations
type DeleteParams struct {
	UUID    *AssetUUID
	UUIDs   []AssetUUID
	Filters *AssetFilters
}

// NewDeleteParamsWithUUID creates DeleteParams for single asset deletion
func NewDeleteParamsWithUUID(uuid AssetUUID) DeleteParams {
	return DeleteParams{
		UUID: &uuid,
	}
}

// NewDeleteParamsWithUUIDs creates DeleteParams for multiple asset deletion
func NewDeleteParamsWithUUIDs(uuids []AssetUUID) DeleteParams {
	return DeleteParams{
		UUIDs: uuids,
	}
}

// NewDeleteParamsWithFilters creates DeleteParams for filtered deletion
func NewDeleteParamsWithFilters(filters AssetFilters) DeleteParams {
	return DeleteParams{
		Filters: &filters,
	}
}

// NewDeleteParamsForAll creates DeleteParams for deleting all assets
func NewDeleteParamsForAll() DeleteParams {
	return DeleteParams{}
}
