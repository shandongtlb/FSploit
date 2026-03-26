package org.fsploit.android.ui

import android.content.Context
import android.widget.ArrayAdapter
import android.widget.Filter
import android.widget.Filterable
import com.google.android.material.textfield.MaterialAutoCompleteTextView

class NonFilteringStringAdapter(
    context: Context,
    items: List<String>
) : ArrayAdapter<String>(context, android.R.layout.simple_dropdown_item_1line, items.toMutableList()),
    Filterable {

    private val allItems = items.toList()

    override fun getFilter(): Filter {
        return object : Filter() {
            override fun performFiltering(constraint: CharSequence?): FilterResults {
                return FilterResults().apply {
                    values = allItems
                    count = allItems.size
                }
            }

            override fun publishResults(constraint: CharSequence?, results: FilterResults?) {
                clear()
                addAll(allItems)
                notifyDataSetChanged()
            }
        }
    }
}

fun MaterialAutoCompleteTextView.enableFullDropdown() {
    threshold = 0
    setOnClickListener { showDropDown() }
    setOnFocusChangeListener { _, hasFocus ->
        if (hasFocus) {
            post { showDropDown() }
        }
    }
}
